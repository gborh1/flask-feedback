"""Initial migration.

Revision ID: 656bb3c0a09d
Revises: 
Create Date: 2020-07-28 13:30:13.298188

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '656bb3c0a09d'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('is_admin', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'is_admin')
    # ### end Alembic commands ###
