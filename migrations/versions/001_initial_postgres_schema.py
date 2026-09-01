"""Initial PostgreSQL production schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-01 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Sequences
    op.execute("CREATE SEQUENCE IF NOT EXISTS anonymous_student_id_seq START WITH 101 INCREMENT BY 1 NO CYCLE;")

    # 2. Students table
    op.create_table(
        'students',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('anonymous_id', sa.Integer(), nullable=False, unique=True),
        sa.Column('user_hash', sa.String(length=64), nullable=False, unique=True),
        sa.Column('enc_telegram_id', sa.Text(), nullable=False),
        sa.Column('enc_full_name', sa.Text(), nullable=True),
        sa.Column('enc_username', sa.Text(), nullable=True),
        sa.Column('is_banned', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('ban_reason', sa.Text(), nullable=True),
        sa.Column('muted_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_posts', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('total_replies', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('last_active_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_students_hash', 'students', ['user_hash'])
    op.create_index('idx_students_anon', 'students', ['anonymous_id'])

    # 3. Banned fingerprints
    op.create_table(
        'banned_fingerprints',
        sa.Column('id_hash', sa.String(length=64), primary_key=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('banned_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )

    # 4. Admin credentials
    op.create_table(
        'admin_credentials',
        sa.Column('telegram_id', sa.BigInteger(), primary_key=True),
        sa.Column('password_hash', sa.Text(), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    )

    # 5. Security events
    op.create_table(
        'security_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.BigInteger(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_security_events_lookup', 'security_events', ['user_id', 'event_type', 'created_at'])

    # 6. Admin login attempts
    op.create_table(
        'admin_login_attempts',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.BigInteger(), nullable=False),
        sa.Column('attempted_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_admin_login_attempts_lookup', 'admin_login_attempts', ['user_id', 'attempted_at'])

    # 7. Admin sessions
    op.create_table(
        'admin_sessions',
        sa.Column('user_id', sa.BigInteger(), primary_key=True),
        sa.Column('authenticated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('role', sa.String(length=32), nullable=False),
    )

    # 8. Posts
    op.create_table(
        'posts',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('anonymous_id', sa.Integer(), sa.ForeignKey('students.anonymous_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('channel_message_id', sa.BigInteger(), nullable=False, unique=True),
        sa.Column('user_msg_id', sa.BigInteger(), nullable=False),
        sa.Column('media_type', sa.String(length=32), nullable=False),
        sa.Column('media_file_id', sa.Text(), nullable=True),
        sa.Column('content_preview', sa.Text(), nullable=True),
        sa.Column('content_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('status', sa.String(length=32), nullable=False, server_default=sa.text("'published'")),
        sa.Column('enc_original_filename', sa.Text(), nullable=True),
    )
    op.create_index('idx_posts_channel_msg', 'posts', ['channel_message_id'])
    op.create_index('idx_posts_hash_created', 'posts', ['content_hash', 'created_at'])

    # 9. Replies
    op.create_table(
        'replies',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('parent_channel_msg_id', sa.BigInteger(), nullable=False),
        sa.Column('reply_channel_msg_id', sa.BigInteger(), nullable=False, unique=True),
        sa.Column('anonymous_id', sa.Integer(), sa.ForeignKey('students.anonymous_id', ondelete='RESTRICT'), nullable=False),
        sa.Column('media_type', sa.String(length=32), nullable=False),
        sa.Column('media_file_id', sa.Text(), nullable=True),
        sa.Column('content_preview', sa.Text(), nullable=True),
        sa.Column('content_hash', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('status', sa.String(length=32), nullable=False, server_default=sa.text("'published'")),
        sa.Column('enc_original_filename', sa.Text(), nullable=True),
    )
    op.create_index('idx_replies_parent', 'replies', ['parent_channel_msg_id'])
    op.create_index('idx_replies_msg', 'replies', ['reply_channel_msg_id'])
    op.create_index('idx_replies_hash_created', 'replies', ['content_hash', 'created_at'])

    # 10. Submission quotas
    op.create_table(
        'submission_quotas',
        sa.Column('user_hash', sa.String(length=64), nullable=False),
        sa.Column('window_hour', sa.String(length=32), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False, server_default=sa.text('1')),
        sa.PrimaryKeyConstraint('user_hash', 'window_hour')
    )
    op.create_index('idx_quotas_window', 'submission_quotas', ['window_hour'])

    # 11. Audit logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('admin_id', sa.BigInteger(), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('target_anonymous_id', sa.Integer(), nullable=True),
        sa.Column('details', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_audit_logs_created', 'audit_logs', ['created_at'])

    # 12. System settings
    op.create_table(
        'system_settings',
        sa.Column('key', sa.String(length=64), primary_key=True),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )


def downgrade() -> None:
    op.drop_table('system_settings')
    op.drop_table('audit_logs')
    op.drop_table('submission_quotas')
    op.drop_table('replies')
    op.drop_table('posts')
    op.drop_table('admin_sessions')
    op.drop_table('admin_login_attempts')
    op.drop_table('security_events')
    op.drop_table('admin_credentials')
    op.drop_table('banned_fingerprints')
    op.drop_table('students')
    op.execute("DROP SEQUENCE IF EXISTS anonymous_student_id_seq;")
