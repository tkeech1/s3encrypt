from abc import ABC, abstractmethod
import typing


class FileEncryptDecrypt(ABC):
    @abstractmethod
    def encrypt_file(self) -> None:
        raise NotImplementedError("Not implemented")

    @abstractmethod
    def decrypt_file(self) -> None:
        raise NotImplementedError("Not implemented")


class EncryptionError(Exception):
    # Generic exception for the s3encrypt.encrypter module used to wrap
    # exceptions generated by dependencies.

    def __init__(self, msg: str, original_exception: Exception = Exception()):
        super(EncryptionError, self).__init__(f"{msg}: {original_exception}")
        self.original_exception = original_exception


# TODO: Fix use of typing.Any
class EncryptionFactory:
    def __init__(self) -> None:
        self._builders: typing.Dict[str, typing.Any] = {}

    def register_builder(self, key: str, builder: typing.Any) -> None:
        self._builders[key] = builder

    def create(self, key: str, **kwargs: typing.Dict[str, typing.Any]) -> typing.Any:
        builder = self._builders.get(key)
        if not builder:
            raise ValueError(key)
        return builder(**kwargs)
