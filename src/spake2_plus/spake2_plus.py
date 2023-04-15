from hashlib import sha256

from spake2.spake2 import (
    _SPAKE2_Base,
    _SPAKE2_Asymmetric,
    SideA,
    SideB,
    ParamsEd25519,
    ReflectionThwarted,
    OnlyCallFinishOnce,
)

DefaultParams = ParamsEd25519


def finalize_SPAKE2_Plus(shared_key, X_msg, Y_msg, K_bytes, K_bytes_2):
    transcript = b"".join([
        sha256(shared_key).digest(), X_msg, Y_msg,
        K_bytes, K_bytes_2
    ])
    key = sha256(transcript).digest()
    return key

class _SPAKE2_Plus_Base(_SPAKE2_Base):
    def finish(self, inbound_side_and_message):
        if self._finished:
            raise OnlyCallFinishOnce("finish() can only be called once")
        self._finished = True

        self.inbound_message = self._extract_message(inbound_side_and_message)

        g = self.params.group # this is obviously G
        inbound_elem = g.bytes_to_element(self.inbound_message) # G^beta*N^pw
        if inbound_elem.to_bytes() == self.outbound_message:
            raise ReflectionThwarted
        #K_elem = (inbound_elem + (self.my_unblinding() * -self.pw_scalar)
        #          ) * self.xy_scalar
        pw_unblinding = self.my_unblinding().scalarmult(-self.pw_scalar) # N^-pw
        K_elem = inbound_elem.add(pw_unblinding).scalarmult(self.xy_scalar) # (v*N^-pw)^alpha
        K_bytes = K_elem.to_bytes() # also known as w
        K_bytes_2 = self.get_K_bytes_2()
        key = self._finalize(K_bytes, K_bytes_2)
        return key
    
    def _finalize(self, K_bytes, K_bytes_2):
        return finalize_SPAKE2_Plus(self.pw, self.X_msg(), self.Y_msg(), K_bytes, K_bytes_2)

    def get_K_bytes_2(self):
        raise NotImplementedError()

class _SPAKE2_Plus_Asymmetric(_SPAKE2_Plus_Base, _SPAKE2_Asymmetric):
    ...

class SPAKE2_Plus_A(_SPAKE2_Plus_Asymmetric):
    side = SideA
    def my_blinding(self): return self.params.M
    def my_unblinding(self): return self.params.N
    def X_msg(self): return self.outbound_message
    def Y_msg(self): return self.inbound_message

    def __init__(self, password, user_secret, *args, params=DefaultParams, **kwargs):
        super(_SPAKE2_Plus_Asymmetric, self).__init__(password, *args, **kwargs)
        self.usr_sec = user_secret
        self.usr_sec_scalar = params.group.password_to_scalar(user_secret)

    def get_K_bytes_2(self):
        pw_unblinding = self.my_unblinding().scalarmult(-self.pw_scalar) # N^-pw

        g = self.params.group
        inbound_elem = g.bytes_to_element(self.inbound_message)
        k_elem = inbound_elem.add(pw_unblinding).scalarmult(self.usr_sec_scalar)
        return k_elem.to_bytes()

class SPAKE2_Plus_B(_SPAKE2_Plus_Asymmetric):
    side = SideB
    def my_blinding(self): return self.params.N
    def my_unblinding(self): return self.params.M
    def X_msg(self): return self.inbound_message
    def Y_msg(self): return self.outbound_message

    def __init__(self, password, password_verifier, *args, params=DefaultParams, **kwargs):
        super(_SPAKE2_Plus_Asymmetric, self).__init__(password, *args, **kwargs)
        self.pwd_verifier = password_verifier
        # self.pwd_ver_scalar = params.group.password_to_scalar(password_verifier)
    
    @staticmethod
    def _convert_pass_to_encoding(pwd):
        params = DefaultParams
        g = params.group
        pwd_scalar = g.password_to_scalar(pwd)
        pwd_elem = g.Base.scalarmult(pwd_scalar)
        return pwd_elem
    
    def get_K_bytes_2(self):
        k_elem = self.pwd_verifier.scalarmult(self.xy_scalar)
        return k_elem.to_bytes()