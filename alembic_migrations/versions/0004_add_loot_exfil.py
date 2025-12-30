"""add loot exfil tracking tables

Revision ID: 0004
Revises: 0003
Create Date: 2025-12-30

"""

from alembic import op
import sqlalchemy as sa

revision = "0004_add_loot_exfil"
down_revision = "0003_add_lateral_movement"
branch_labels = None
depends_on = None


def upgrade():
    # Exfil results table
    op.create_table(
        'exfil_results',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('item_name', sa.String(255), nullable=True),
        sa.Column('item_type', sa.String(50), nullable=True),
        sa.Column('method', sa.String(50), nullable=True),
        sa.Column('size_bytes', sa.Integer(), nullable=True),
        sa.Column('content_hash', sa.String(64), nullable=True),
        sa.Column('status', sa.String(50), nullable=True),
        sa.Column('exfil_timestamp', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_index(op.f('ix_exfil_results_id'), 'exfil_results', ['id'], unique=False)
    op.create_index(op.f('ix_exfil_results_scan_id'), 'exfil_results', ['scan_id'], unique=False)
    
    # Blockchain publishing records
    op.create_table(
        'blockchain_records',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('item_name', sa.String(255), nullable=True),
        sa.Column('blockchain_type', sa.String(50), nullable=True),
        sa.Column('cid', sa.String(255), nullable=True),
        sa.Column('tx_hash', sa.String(255), nullable=True),
        sa.Column('content_hash', sa.String(64), nullable=True),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_index(op.f('ix_blockchain_records_id'), 'blockchain_records', ['id'], unique=False)


def downgrade():
    op.drop_table('blockchain_records')
    op.drop_table('exfil_results')
