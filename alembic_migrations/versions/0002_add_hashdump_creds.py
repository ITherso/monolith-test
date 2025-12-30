"""add hashdump and cracked credentials tables

Revision ID: 0002
Revises: 0001_initial
Create Date: 2025-12-30

"""

from alembic import op
import sqlalchemy as sa

revision = "0002_add_hashdump_creds"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    # Hash dump tabloları
    op.create_table(
        'hash_dumps',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('hostname', sa.String(255), nullable=True),
        sa.Column('hash_type', sa.String(50), nullable=True),
        sa.Column('username', sa.String(255), nullable=True),
        sa.Column('nthash', sa.String(255), nullable=True),
        sa.Column('lmhash', sa.String(255), nullable=True),
        sa.Column('dumped_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_index(op.f('ix_hash_dumps_id'), 'hash_dumps', ['id'], unique=False)
    op.create_index(op.f('ix_hash_dumps_scan_id'), 'hash_dumps', ['scan_id'], unique=False)
    
    # Cracked credentials tablosu
    op.create_table(
        'cracked_credentials',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=True),
        sa.Column('username', sa.String(255), nullable=True),
        sa.Column('password', sa.String(255), nullable=True),
        sa.Column('hash_source', sa.String(100), nullable=True),
        sa.Column('cracked_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    op.create_index(op.f('ix_cracked_credentials_id'), 'cracked_credentials', ['id'], unique=False)
    op.create_index(op.f('ix_cracked_credentials_scan_id'), 'cracked_credentials', ['scan_id'], unique=False)


def downgrade():
    op.drop_table('cracked_credentials')
    op.drop_table('hash_dumps')
