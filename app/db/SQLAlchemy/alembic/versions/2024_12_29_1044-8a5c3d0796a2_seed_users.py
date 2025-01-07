"""seed users

Revision ID: 8a5c3d0796a2
Revises: 67c5fd0054fe
Create Date: 2024-12-29 10:44:47.426893

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.api.utils.crypt import hash_password
from app.core.config import settings, AlembicTestData

# revision identifiers, used by Alembic.
revision: str = '8a5c3d0796a2'
down_revision: Union[str, None] = '67c5fd0054fe'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

table_user = sa.sql.table(
    'users',
    sa.sql.column('username', sa.String()),
    sa.sql.column('hashed_password', sa.String()),
    sa.sql.column('email', sa.String()),
    sa.sql.column('role_id', sa.Integer()),
    sa.sql.column('born', sa.Date()),
    sa.sql.column('verified', sa.Boolean()),
    sa.sql.column('refresh_token', sa.String()),
    sa.sql.column('verify_code', sa.String()),
    sa.sql.column('reset_code', sa.String()),
)

def upgrade() -> None:
    default_users = []
    if not AlembicTestData.flag_test:
        default_users.append(
            {
                'username': settings.DEFAULT_USERNAME,
                'hashed_password': hash_password(settings.DEFAULT_PASSWORD.get_secret_value()),
                'email': settings.DEFAULT_EMAIL,
                'role_id': 2,
                'born': '2024-12-29',
                'verified': True,
            }
        )
    else:
        default_users.extend(AlembicTestData.users)
    op.bulk_insert(table_user, default_users)


def downgrade() -> None:
    op.get_bind().execute(
        table_user.delete()
    )
