"""add lateral movement tracking tables

Revision ID: 0003
Revises: 0002
Create Date: 2025-12-30

"""

from alembic import op
import sqlalchemy as sa

revision = "0003_add_lateral_movement"
down_revision = "0002_add_hashdump_creds"
branch_labels = None
depends_on = None


def upgrade():
    # Lateral movement results table
    op.create_table(
        'lateral_movement',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('source_host', sa.String(255), nullable=True),
        sa.Column('target_host', sa.String(255), nullable=True),
        sa.Column('method', sa.String(50), nullable=True),
        sa.Column('username', sa.String(255), nullable=True),
        sa.Column('status', sa.String(50), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_index(op.f('ix_lateral_movement_id'), 'lateral_movement', ['id'], unique=False)
    op.create_index(op.f('ix_lateral_movement_scan_id'), 'lateral_movement', ['scan_id'], unique=False)
    
    # Pivot chain tracking
    op.create_table(
        'pivot_chains',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('chain_depth', sa.Integer(), nullable=True),
        sa.Column('hosts_visited', sa.Text(), nullable=True),
        sa.Column('pivot_path', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_index(op.f('ix_pivot_chains_id'), 'pivot_chains', ['id'], unique=False)


def downgrade():
    op.drop_table('pivot_chains')
    op.drop_table('lateral_movement')
