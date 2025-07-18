from pydantic import BaseModel


class PostgresValidation(BaseModel):

    user: str
    password: str
    database: str
    host: str
    port: int
