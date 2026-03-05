"""extend schema with intelligence fields and file_scans table

Revision ID: 0001_extend_schema
Revises: 
Create Date: 2026-03-04 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_extend_schema'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # add intelligence columns to scan_results
    op.add_column('scan_results', sa.Column('structural_score', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scan_results', sa.Column('vt_score', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scan_results', sa.Column('ioc_score', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scan_results', sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('scan_results', sa.Column('signals_json', sa.JSON(), nullable=False, server_default='{}'))
    op.add_column('scan_results', sa.Column('vt_raw_json', sa.JSON(), nullable=False, server_default='{}'))
    op.add_column('scan_results', sa.Column('summary', sa.Text(), nullable=False, server_default=''))
    op.create_index(op.f('ix_scan_results_scan_id'), 'scan_results', ['scan_id'], unique=False)

    # create file_scans table
    op.create_table(
        'file_scans',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('filename', sa.String(), nullable=False),
        sa.Column('sha256', sa.String(), nullable=False),
        sa.Column('vt_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('vt_raw_json', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    op.create_index(op.f('ix_file_scans_sha256'), 'file_scans', ['sha256'], unique=False)
    op.create_index(op.f('ix_file_scans_user_id'), 'file_scans', ['user_id'], unique=False)

    # add index to scans.user_id (might already exist)
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'], unique=False)
    # add index to ioc.value
    op.create_index(op.f('ix_ioc_value'), 'ioc', ['value'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_ioc_value'), table_name='ioc')
    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
    op.drop_index(op.f('ix_file_scans_user_id'), table_name='file_scans')
    op.drop_index(op.f('ix_file_scans_sha256'), table_name='file_scans')
    op.drop_table('file_scans')
    op.drop_index(op.f('ix_scan_results_scan_id'), table_name='scan_results')
    op.drop_column('scan_results', 'summary')
    op.drop_column('scan_results', 'vt_raw_json')
    op.drop_column('scan_results', 'signals_json')
    op.drop_column('scan_results', 'risk_score')
    op.drop_column('scan_results', 'ioc_score')
    op.drop_column('scan_results', 'vt_score')
    op.drop_column('scan_results', 'structural_score')
