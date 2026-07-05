"""Add missing columns to lateral_movement table

Revision ID: 0005_lateral_extended
Revises: 0004_add_loot_exfil
Create Date: 2026-05-20

"""

from alembic import op
import sqlalchemy as sa

revision = "0005_lateral_extended"
down_revision = "0004_add_loot_exfil"
branch_labels = None
depends_on = None


def upgrade():
    # Add missing columns to lateral_movement
    op.add_column('lateral_movement', sa.Column('error_message', sa.Text(), nullable=True))
    op.add_column('lateral_movement', sa.Column('command_output', sa.Text(), nullable=True))
    op.add_column('lateral_movement', sa.Column('execution_time', sa.Float(), nullable=True))
    op.add_column('lateral_movement', sa.Column('source_host', sa.String(255), nullable=True))
    op.add_column('lateral_movement', sa.Column('credentials_type', sa.String(50), nullable=True))
    op.add_column('lateral_movement', sa.Column('access_level', sa.String(50), nullable=True))


def downgrade():
    op.drop_column('lateral_movement', 'access_level')
    op.drop_column('lateral_movement', 'credentials_type')
    op.drop_column('lateral_movement', 'source_host')
    op.drop_column('lateral_movement', 'execution_time')
    op.drop_column('lateral_movement', 'command_output')
    op.drop_column('lateral_movement', 'error_message')
