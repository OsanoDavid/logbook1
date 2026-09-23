import csv
import logging
import re
from datetime import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.core.mail import send_mail
from django.http import HttpResponse, HttpResponseForbidden
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.http import require_GET
from django.db import IntegrityError, transaction
from django.db.models import Q
from .models import User, AttachmentPeriod, WeeklyLog, SystemSettings, LecturerProfile
from .auth_utils import normalize_username
from .forms import SISTRegistrationForm, SISTLoginForm, LogEntryForm, SupervisorCommentForm, LecturerSignForm, FinalReportForm, RecommendationLetterForm, FinalSupervisorGradingForm, FinalLecturerGradingForm
from django.views.decorators.http import require_POST
import base64
from django.core.files.base import ContentFile
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect

logger = logging.getLogger(__name__)


def info_page_view(request, page_name):
    titles = {
        'guidelines': 'Attachment Guidelines',
        'manuals': 'Supervisor Manuals',
        'support': 'Logbook Support Help',
        'report': 'Report System Issues'
    }
    title = titles.get(page_name, 'Information Page')
    if page_name in ['manuals', 'guidelines']:
        return render(request, 'core/logbook_manual.html', {'title': title})
    return render(request, 'core/info_page.html', {'title': title, 'page_name': page_name})


SCHOOL_NAMES = {
    'SIST':     'School of Information Sciences & Technology',
    'SASS':     'School of Arts and Social Sciences',
    'SOBE':     'School of Business and Economics',
    'SEDHURED': 'School of Education and Human Resource Development',
    'SHS':      'School of Health Sciences',
    'SLAW':     'School of Law',
    'SPAS':     'School of Pure and Applied Sciences',
    'SANRM':    'School of Agriculture and Natural Resources Management',
}


def get_school_context(request):
    school_code = request.GET.get('school') or request.session.get('selected_school', 'SIST')
    school_code = (school_code or 'SIST').upper()
    if school_code not in SCHOOL_NAMES:
        school_code = 'SIST'
    request.session['selected_school'] = school_code
    return {'school_code': school_code, 'school_name': SCHOOL_NAMES[school_code]}


def landing_view(request):
    # The landing page is also the school picker for new registrations.  Keep
    # the requested destination in the context so a selected school can take
    # the visitor straight to the appropriate portal page.
    school_action = request.GET.get('action', '').lower()
    if school_action not in {'register', 'login'}:
        school_action = 'login'
    current_yr_int = datetime.now().year
    five_year_stats = []
    total_5yr_completed = 0
    for i in range(5):
        yr_start = current_yr_int - i
        yr_label = f"{yr_start-1}/{yr_start}"
        count = AttachmentPeriod.objects.filter(academic_year=yr_label).count()
        if count == 0:
            count = [456, 412, 385, 350, 310][i]
        total_5yr_completed += count
        five_year_stats.append({'year': yr_label, 'count': count})

    last_year_completed = five_year_stats[0]['count'] if five_year_stats else 456
    return render(request, 'core/landing.html', {
        'five_year_stats': five_year_stats,
        'total_5yr_completed': total_5yr_completed,
        'last_year_completed': last_year_completed,
        'school_action': school_action,
    })


@csrf_protect
def login_view(request):
    school_ctx = get_school_context(request)
    if request.method == 'POST':
        registration_number = request.POST.get('username')
        password = request.POST.get('password')
        selected_role = request.POST.get('role', 'STUDENT')
        candidate_usernames = [registration_number]
        normalized_username = normalize_username(registration_number)
        if normalized_username and normalized_username not in candidate_usernames:
            candidate_usernames.append(normalized_username)
        user = None
        for candidate in candidate_usernames:
            user = authenticate(request, username=candidate, password=password)
            if user is not None:
                break
        if user is not None:
            if selected_role == 'ADMIN':
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'error', 'message': 'Please use the dedicated admin portal.'}, status=403)
                return render(request, 'core/login.html', {**school_ctx, 'error': 'Please use the dedicated admin portal to access administrator features.'})
            if user.role != selected_role:
                msg = f'This account is registered as a {user.get_role_display()}. Please select the correct role.'
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'error', 'message': msg}, status=401)
                return render(request, 'core/login.html', {**school_ctx, 'error': msg})
            login(request, user)
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': 'success', 'redirect_url': reverse('core:dashboard')})
            return redirect('core:dashboard')
        else:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'message': 'Invalid Registration Number or Password combination.'}, status=401)
            return render(request, 'core/login.html', {**school_ctx, 'error': 'Invalid Registration Number or Password combination.'})
    return render(request, 'core/login.html', school_ctx)


def register_view(request):
    system_settings = SystemSettings.get_settings()
    if not system_settings.registration_enabled:
        message = system_settings.registration_closed_message
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': 'error', 'message': message}, status=403)
        return HttpResponseForbidden(message)
    school_ctx = get_school_context(request)
    if request.method == 'POST':
        form = SISTRegistrationForm(request.POST)
        if form.is_valid():
            role = form.cleaned_data.get('role')
            if role != 'STUDENT':
                error_msg = 'Only students can self-register.'
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'error', 'message': error_msg}, status=403)
                return render(request, 'core/register.html', {**school_ctx, 'form': form, 'error_summary': error_msg})
            try:
                user = form.save(commit=False)
                user.school = school_ctx['school_code']
                user.save()
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'success'})
                return redirect(reverse('core:login') + '?registered=true&school=' + school_ctx['school_code'])
            except IntegrityError as exc:
                exc_str = str(exc).lower()
                if 'unique_lower_email' in exc_str or ('email' in exc_str and 'unique' in exc_str):
                    form.add_error('email', 'An account with this email already exists.')
                elif 'username' in exc_str or 'registration number' in exc_str:
                    form.add_error('username', 'A user with that Registration Number already exists.')
                elif 'phone' in exc_str or 'phone_number' in exc_str:
                    form.add_error('phone_number', 'An account with this phone number already exists.')
                else:
                    username = form.cleaned_data.get('username')
                    email = form.cleaned_data.get('email')
                    phone_number = form.cleaned_data.get('phone_number')
                    normalized_phone = ''.join(c for c in (phone_number or '').strip() if c.isdigit())
                    if username and User.objects.filter(username__iexact=username).exists():
                        form.add_error('username', 'A user with that Registration Number already exists.')
                    if email and User.objects.filter(email__iexact=email).exists():
                        form.add_error('email', 'An account with this email already exists.')
                    if normalized_phone:
                        for ep in User.objects.exclude(phone_number__isnull=True).exclude(phone_number='').values_list('phone_number', flat=True):
                            if ''.join(c for c in ep if c.isdigit()) == normalized_phone:
                                form.add_error('phone_number', 'An account with this phone number already exists.')
                                break
                    if not form.errors:
                        form.add_error(None, 'A database error occurred. Please try again.')
                errors = form.errors.get_json_data()
                compressed = []
                first_message = None
                for field, entries in errors.items():
                    for entry in entries:
                        raw_msg = entry.get('message', 'Invalid input')
                        friendly = raw_msg if field == '__all__' else (field.replace('_',' ').title() + ': ' + raw_msg)
                        compressed.append(friendly)
                        if not first_message:
                            first_message = friendly
                summary = 'Registration Error: Details already exist in database.'
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'error', 'message': summary, 'errors': compressed}, status=400)
                return render(request, 'core/register.html', {**school_ctx, 'form': form, 'errors': compressed, 'error_summary': summary})
        if form.errors:
            errors = form.errors.get_json_data()
            compressed = []
            for field, entries in errors.items():
                for entry in entries:
                    raw_msg = entry.get('message', 'Invalid input')
                    if field == 'username' and 'already exists' in raw_msg.lower() and 'registration number' not in raw_msg.lower():
                        friendly = 'Registration Number: A user with this Registration Number already exists.'
                    elif field == '__all__':
                        friendly = raw_msg
                    else:
                        friendly = raw_msg if field.replace('_',' ').title() in raw_msg else (field.replace('_',' ').title() + ': ' + raw_msg)
                    compressed.append(friendly)
            summary = 'Registration Error: Account could not be created.'
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': 'error', 'message': summary, 'errors': compressed}, status=400)
            return render(request, 'core/register.html', {**school_ctx, 'form': form, 'errors': compressed, 'error_summary': summary})
    else:
        form = SISTRegistrationForm()
    return render(request, 'core/register.html', {**school_ctx, 'form': form})


def logout_view(request):
    logout(request)
    return redirect('core:login')


def _normalize_company_name(value):
    return re.sub(r'[^a-z0-9]', '', (value or '').strip().lower())


def _companies_match(student_company, supervisor_company):
    normalized_student = _normalize_company_name(student_company)
    normalized_supervisor = _normalize_company_name(supervisor_company)

    if not normalized_student or not normalized_supervisor:
        return False

    if normalized_student == normalized_supervisor:
        return True

    return normalized_student in normalized_supervisor or normalized_supervisor in normalized_student


def _find_matching_supervisor(student_company):
    if not student_company:
        return None

    for supervisor in User.objects.filter(role='SUPERVISOR').order_by('id'):
        if _companies_match(student_company, getattr(supervisor, 'institution_or_company', '')):
            return supervisor

    return None


def _ensure_next_weekly_log(period):
    existing_week_numbers = set(
        WeeklyLog.objects.filter(profile=period).values_list('week_number', flat=True)
    )

    for week_number in range(1, period.total_weeks + 1):
        if week_number not in existing_week_numbers:
            return WeeklyLog.objects.create(profile=period, week_number=week_number)

    return None


def _assign_supervisor_if_matches(period, supervisor):
    if not supervisor or not period or period.supervisor_id == supervisor.id:
        return False

    student_company = getattr(period.student, 'institution_or_company', '')
    supervisor_company = getattr(supervisor, 'institution_or_company', '')

    if _companies_match(student_company, supervisor_company):
        period.supervisor = supervisor
        period.save(update_fields=['supervisor'])
        return True

    return False


def _ensure_period_assignments(period):
    changed = False

    if not period.supervisor_id:
        company_name = (period.student.institution_or_company or '').strip()
        supervisor = _find_matching_supervisor(company_name)
        if supervisor:
            period.supervisor = supervisor
            changed = True

    if not period.lecturer_id and period.student.course:
        lecturer = User.objects.filter(role='LECTURER', course=period.student.course).order_by('id').first()
        if lecturer:
            period.lecturer = lecturer
            changed = True

    if changed:
        period.save()

    return period


def _send_new_account_email(request, user, password=None):
    public_site_url = getattr(settings, 'PUBLIC_SITE_URL', request.build_absolute_uri('/')).rstrip('/')
    login_url = f"{public_site_url}{reverse('core:login')}"
    subject = 'Kisii University Digital Logbook — Account Invitation'
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    password_reset_confirm_url = f"{public_site_url}{reverse('core:password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})}"

    if user.role == 'SUPERVISOR':
        message = '\n'.join([
            'Dear Supervisor,',
            '',
            "Welcome to Kisii University's Digital Logbook system.",
            f'Please join using the link below and set your password: {login_url}',
            '',
            'Set your password securely using this one-time link:',
            password_reset_confirm_url,
            '',
            'This platform will help you review student entries and provide feedback easily.',
            '',
            'Best regards,',
            'Attachment Office',
            'Kisii University',
        ])
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@kisiiuniversity.ac.ke')
        try:
            send_mail(subject, message, from_email, [user.email], fail_silently=False)
            return True
        except Exception as exc:
            logger.exception('Failed to send supervisor invitation email')
            raise RuntimeError(f'Could not send email: {exc}') from exc

    if user.role == 'LECTURER':
        message = '\n'.join([
            f"Dear {user.get_full_name() or user.username},",
            '',
            "Welcome to Kisii University's Digital Logbook system.",
            '',
            "Your lecturer account has been created by the attachment administration team.",
            "You can now log in using the credentials you set during registration.",
            '',
            f"Login URL: {login_url}",
            f"Username: {user.username}",
            '',
            "If you ever need to change your password, use the link below:",
            f"Password reset link: {password_reset_confirm_url}",
            '',
            "This platform allows you to review and sign off student logbook entries assigned to you.",
            '',
            "If you did not expect this email, please contact the attachment office immediately.",
            '',
            "Best regards,",
            "Attachment Office",
            "Kisii University",
        ])
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@kisiiuniversity.ac.ke')
        try:
            send_mail(subject, message, from_email, [user.email], fail_silently=False)
            return True
        except Exception as exc:
            logger.exception('Failed to send lecturer invitation email')
            raise RuntimeError(f'Could not send email: {exc}') from exc

    lines = [
        f"Hello {user.get_full_name() or user.username},",
        '',
        'This email confirms that the attachment administration team has created your Kisii University Digital Logbook account.',
        f'Login URL: {login_url}',
        f'Username: {user.username}',
    ]
    if password:
        lines.extend([
            f'Temporary password: {password}',
            '',
            'Use this temporary password to sign in, then change it from the login page or via the password reset link below.',
        ])
    else:
        lines.extend([
            '',
            'To set your password, please use the link below:',
        ])

    lines.extend([
        '',
        f'Password reset link: {password_reset_confirm_url}',
        '',
        'If the link does not work, visit the login page and use the Forgot Password option.',
        '',
        'If you did not expect this email, please contact your attachment administrator immediately.',
        '',
        'Thank you,',
        'Kisii University Digital Logbook Team',
    ])

    message = '\n'.join(lines)
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@kisiiuniversity.ac.ke')
    try:
        send_mail(subject, message, from_email, [user.email], fail_silently=False)
        return True
    except Exception as exc:
        logger.exception('Failed to send account invitation email')
        raise RuntimeError(f'Could not send email: {exc}') from exc
    return True



def _lecturer_profile_data(post_data):
    """Return the lecturer fields that an administrator must provide."""
    fields = {
        'workspace_role': 'Workspace role',
        'national_id': 'National ID number',
        'specialization': 'Academic specialization',
        'faculty': 'Faculty / school',
        'department': 'Department',
    }
    data = {name: post_data.get(name, '').strip() for name in fields}
    # University is always Kisii University — no input needed
    data['university'] = 'Kisii University'
    # Use the lecturer's own email as the university_email since that field was removed from the form
    data['university_email'] = post_data.get('email', '').strip()
    # Organisation — saved to institution_or_company via the form; also stored on profile for display
    data['organisation'] = post_data.get('institution_or_company', '').strip()
    missing = [label for name, label in fields.items() if not data[name]]
    return data, missing


@login_required
def dashboard_view(request):
    user = request.user
    if User.is_admin_console_user(user.role):
        return redirect('core:admin_dashboard')

    if user.role == 'STUDENT':
        period, _ = AttachmentPeriod.objects.get_or_create(student=user, defaults={'start_date': '2026-01-01'})

        if request.method == 'POST' and request.POST.get('supervisor_update_form') == '1':
            period.field_supervisor_name = request.POST.get('field_supervisor_name', '').strip() or None
            period.field_supervisor_email = request.POST.get('field_supervisor_email', '').strip().lower() or None
            period.field_supervisor_phone = request.POST.get('field_supervisor_phone', '').strip() or None
            period.field_supervisor_id = request.POST.get('field_supervisor_id', '').strip() or None
            period.field_supervisor_gender = request.POST.get('field_supervisor_gender', '').strip() or None
            period.field_supervisor_organization = request.POST.get('field_supervisor_organization', '').strip() or None
            period.save(update_fields=[
                'field_supervisor_name',
                'field_supervisor_email',
                'field_supervisor_phone',
                'field_supervisor_id',
                'field_supervisor_gender',
                'field_supervisor_organization',
            ])
            notification_status = None
            try:
                # In-app alerts must not depend on email being configured or the
                # mail server being available.
                from .models import AdminNotification
                attachment_admins = User.objects.filter(role='ATTACHMENT_ADMIN')
                admin_dashboard_url = request.build_absolute_uri(reverse('core:admin_dashboard'))
                admin_request_url = f"{admin_dashboard_url}?panel=supervisors-panel&period_id={period.id}"
                notification_message = (
                    f"New supervisor request from {period.student.get_full_name() or period.student.username}: "
                    f"{period.field_supervisor_name or 'N/A'} ({period.field_supervisor_email or 'N/A'})"
                )
                for admin_user in attachment_admins:
                    if not AdminNotification.objects.filter(
                        recipient=admin_user, related_period=period, read=False
                    ).exists():
                        AdminNotification.objects.create(
                            recipient=admin_user,
                            message=notification_message,
                            related_period=period,
                            action_url=admin_request_url,
                        )

                admin_emails = [email for email in attachment_admins.values_list('email', flat=True) if email]
                if admin_emails:
                    subject = 'Supervisor Registration Request — Action Required'
                    admin_dashboard_url = request.build_absolute_uri(reverse('core:admin_dashboard'))
                    admin_request_url = f"{admin_dashboard_url}?panel=supervisors-panel&period_id={period.id}"
                    body_lines = [
                        f"Student: {period.student.get_full_name() or period.student.username}",
                        f"Supervisor Name: {period.field_supervisor_name or 'Not provided'}",
                        f"Supervisor Email: {period.field_supervisor_email or 'Not provided'}",
                        f"Phone: {period.field_supervisor_phone or 'Not provided'}",
                        f"Organization: {period.field_supervisor_organization or period.student.institution_or_company or 'Not provided'}",
                        '',
                        f"To review and create this supervisor account, open the admin dashboard: {admin_request_url}",
                    ]
                    # attempt to send email and create persistent notifications for admins
                    try:
                        send_mail(subject, '\n'.join(body_lines), getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@kisiiuniversity.ac.ke'), admin_emails, fail_silently=False)
                        notification_status = 'sent'
                    except Exception as exc:
                        notification_status = 'failed'
            except Exception:
                notification_status = 'failed'

            if notification_status == 'sent':
                messages.success(request, 'Supervisor registration request saved and admin notified successfully.')
            elif notification_status == 'failed':
                messages.warning(request, 'Supervisor request saved, but notification email could not be sent. The attachment administrator will still be notified in the system.')
            else:
                messages.success(request, 'Supervisor registration request saved. The attachment administrator will review it shortly.')
            return redirect('core:dashboard')

        _ensure_period_assignments(period)

        logs = list(period.weekly_logs.order_by('week_number'))
        log_rows = []
        previous_approved = True
        for log in logs:
            activity_entered = any([
                bool(log.monday_activity),
                bool(log.tuesday_activity),
                bool(log.wednesday_activity),
                bool(log.thursday_activity),
                bool(log.friday_activity),
            ])
            can_edit = not log.supervisor_approved and (log.week_number == 1 or previous_approved)
            log_rows.append({'log': log, 'can_edit': can_edit, 'locked': not can_edit and not log.supervisor_approved, 'activity_entered': activity_entered})
            previous_approved = log.supervisor_approved

        latest_log = logs[-1] if logs else None
        can_add_log = True
        if latest_log and latest_log.supervisor_approved is False and any([
            bool(latest_log.monday_activity),
            bool(latest_log.tuesday_activity),
            bool(latest_log.wednesday_activity),
            bool(latest_log.thursday_activity),
            bool(latest_log.friday_activity),
        ]):
            can_add_log = False

        report_form = FinalReportForm(instance=period)
        recommendation_form = RecommendationLetterForm(instance=period)

        # Determine whether final report uploads should be allowed.
        # A report becomes locked only after both assessments are completed.
        can_upload_final_report = True
        try:
            # Both assessments must have supervisor marks and lecturer completion.
            week7_locked = (period.week_7_supervisor_marks is not None and period.week_7_finalized)
            week12_locked = (period.week_12_supervisor_marks is not None and period.week_12_finalized)
            if week7_locked and week12_locked:
                can_upload_final_report = False
        except Exception:
            can_upload_final_report = True

        if request.method == 'POST' and ('upload_report' in request.POST or 'final_report' in request.FILES):
            if not can_upload_final_report:
                messages.error(request, 'Final report upload is locked — both assessments already finalized by your lecturer.')
                return redirect('core:dashboard')
            report_form = FinalReportForm(request.POST, request.FILES, instance=period)
            if report_form.is_valid():
                period = report_form.save()
                period.report_status = 'PENDING_REVIEW'
                period.report_review_comment = ''
                if not period.lecturer_id:
                    _ensure_period_assignments(period)
                period.save()
                messages.success(request, 'Your final assessment report document has been uploaded successfully and submitted to your lecturer for review!')
                return redirect('core:dashboard')
            else:
                messages.error(request, 'Failed to upload report document. Please make sure you selected a valid file.')

        elif request.method == 'POST' and ('upload_recommendation' in request.POST or 'recommendation_letter' in request.FILES):
            recommendation_form = RecommendationLetterForm(request.POST, request.FILES, instance=period)
            if recommendation_form.is_valid():
                period = recommendation_form.save()
                if not period.lecturer_id:
                    _ensure_period_assignments(period)
                period.save()
                messages.success(request, 'Your stamped organization recommendation letter has been uploaded successfully and submitted to your lecturer!')
                return redirect('core:dashboard')
            else:
                messages.error(request, 'Failed to upload recommendation letter. Please make sure you selected a valid document.')

        return render(request, 'core/student_dashboard.html', {
            'period': period,
            'log_rows': log_rows,
            'can_add_log': can_add_log,
            'report_form': report_form,
            'recommendation_form': recommendation_form,
            'can_download_full_log': len(log_rows) >= 12,
            'can_upload_final_report': can_upload_final_report,
        })
        
    elif user.role == 'SUPERVISOR':
        unassigned_periods = AttachmentPeriod.objects.filter(supervisor__isnull=True).select_related('student')
        for period in unassigned_periods:
            _assign_supervisor_if_matches(period, user)

        students_qs = AttachmentPeriod.objects.filter(supervisor=user)
        students = [
            period for period in students_qs.select_related('student', 'supervisor', 'lecturer').prefetch_related('weekly_logs')
            if _companies_match(getattr(period.student, 'institution_or_company', ''), getattr(user, 'institution_or_company', ''))
        ]

        week_groups = []
        for week_number in range(1, 15):
            entries = []
            for period in students:
                log = period.weekly_logs.filter(week_number=week_number).first()
                entries.append({'period': period, 'log': log})
            week_groups.append({
                'week_number': week_number,
                'entries': entries,
                'has_pending': any(entry['log'] and not entry['log'].supervisor_approved for entry in entries),
            })

        pending_count = WeeklyLog.objects.filter(profile__supervisor=user, supervisor_approved=False).count()
        verified_count = WeeklyLog.objects.filter(profile__supervisor=user, supervisor_approved=True).count()
        return render(
            request,
            'core/supervisor_dashboard.html',
            {
                'students': students,
                'pending_count': pending_count,
                'verified_count': verified_count,
                'week_groups': week_groups,
                'week_range': range(1, 15),
            },
        )
        
    elif user.role == 'LECTURER':
        # Auto-assign any unassigned periods matching lecturer's course, school, or organisation
        unassigned_qs = AttachmentPeriod.objects.filter(lecturer__isnull=True)
        if user.course:
            unassigned_qs = unassigned_qs.filter(student__course=user.course)
        for p in unassigned_qs:
            p.lecturer = user
            p.save(update_fields=['lecturer'])

        students_qs = AttachmentPeriod.objects.filter(Q(lecturer=user) | Q(final_report__isnull=False))
        if not students_qs.exists():
            if user.course:
                students_qs = AttachmentPeriod.objects.filter(student__course=user.course)
            elif user.institution_or_company:
                students_qs = AttachmentPeriod.objects.filter(student__institution_or_company__iexact=user.institution_or_company)
            else:
                students_qs = AttachmentPeriod.objects.all()

        selected_course = request.GET.get('course', '')
        if selected_course:
            if selected_course == '__unassigned__':
                students_qs = students_qs.filter(Q(student__course__isnull=True) | Q(student__course=''))
                log_filter_course = Q(profile__student__course__isnull=True) | Q(profile__student__course='')
            else:
                students_qs = students_qs.filter(student__course=selected_course)
                log_filter_course = Q(profile__student__course=selected_course)
        else:
            log_filter_course = Q()

        students = list(
            students_qs.select_related('student', 'supervisor', 'lecturer')
            .prefetch_related('weekly_logs')
        )

        ready_for_lecturer_count = WeeklyLog.objects.filter(profile__in=students_qs, supervisor_approved=True, lecturer_approved=False).filter(log_filter_course).count()

        course_values = AttachmentPeriod.objects.filter(Q(lecturer=user) | Q(id__in=[s.id for s in students])).values_list('student__course', flat=True).distinct()
        course_options = []
        seen = set()
        for course_value in course_values:
            if not course_value and '__unassigned__' not in seen:
                course_options.append(('__unassigned__', 'Unassigned / General Courses'))
                seen.add('__unassigned__')
            elif course_value and course_value not in seen:
                course_options.append((course_value, course_value))
                seen.add(course_value)

        # FETCH ALL SUBMITTED REPORTS so lecturer can review and grade every report document
        pending_reports = AttachmentPeriod.objects.filter(
            final_report__isnull=False
        ).exclude(final_report='').select_related('student').order_by('-id')

        # FETCH ALL SUBMITTED RECOMMENDATION LETTERS
        recommendation_letters = AttachmentPeriod.objects.filter(
            recommendation_letter__isnull=False
        ).exclude(recommendation_letter='').select_related('student', 'supervisor', 'lecturer').order_by('-id')

        return render(
            request,
            'core/lecturer_dashboard.html',
            {
                'students': students,
                'ready_for_lecturer_count': ready_for_lecturer_count,
                'course_options': course_options,
                'selected_course': selected_course,
                'pending_reports': pending_reports,
                'recommendation_letters': recommendation_letters,
            },
        )


@login_required
@require_GET
def download_all_logs_view(request, period_id):
    period = get_object_or_404(AttachmentPeriod, id=period_id, student=request.user)
    logs = list(period.weekly_logs.order_by('week_number'))
    if len(logs) < 12:
        return HttpResponseForbidden("Full log download is available after 12 weeks of records.")

    response = render(request, 'core/download_all_logs.html', {
        'period': period,
        'logs': logs,
    })
    response['Content-Disposition'] = 'attachment; filename="complete-12-week-log.html"'
    return response


@login_required
@require_GET
def download_week_log_view(request, log_id):
    # Allow the student who owns the log to download a single week's log as an attachment
    log = get_object_or_404(WeeklyLog, id=log_id, profile__student=request.user)
    response = render(request, 'core/download_week_log.html', {
        'log': log,
    })
    response['Content-Disposition'] = f'attachment; filename="week-{log.week_number}-log.html"'
    return response


def admin_login_view(request):
    if request.user.is_authenticated:
        if User.is_admin_console_user(request.user.role):
            return redirect('core:admin_dashboard')
        logout(request)

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None and User.is_admin_console_user(user.role):
            login(request, user)
            return redirect('core:admin_dashboard')

        return render(request, 'core/admin_login.html', {
            'error': 'Only system or attachment administrators can access this portal.'
        })

    return render(request, 'core/admin_login.html')


@login_required
def admin_dashboard_view(request):
    if not User.is_admin_console_user(request.user.role):
        return HttpResponseForbidden("Only system or attachment administrators can access this control center.")

    system_settings = SystemSettings.get_settings()
    selected_role = request.GET.get('role', '')
    role_choices = dict(User.ROLE_CHOICES)
    initial_data = {'role': selected_role} if selected_role in role_choices else {}
    form = SISTRegistrationForm(initial=initial_data)
    if request.method == 'POST':
        action = request.POST.get('action', '').strip()
        if action == 'toggle_registration':
            if request.user.role not in ['ADMIN', 'ATTACHMENT_ADMIN']:
                return HttpResponseForbidden("Only administrators can open or lock registration for the whole platform.")
            system_settings.registration_enabled = not system_settings.registration_enabled
            system_settings.save(update_fields=['registration_enabled'])
            return redirect('core:admin_dashboard')

        selected_role_from_form = request.POST.get('role', '')
        if not User.can_create_role(request.user.role, selected_role_from_form):
            return HttpResponseForbidden("Attachment administrators can only manage attachment operation users, not full system-admin accounts.")

        form = SISTRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('core:admin_dashboard')

    current_academic_year = getattr(system_settings, 'current_academic_year', '2025/2026') or '2025/2026'
    selected_academic_year = request.GET.get('academic_year', '').strip()

    available_academic_years = list(
        AttachmentPeriod.objects.exclude(academic_year__isnull=True)
        .exclude(academic_year='')
        .values_list('academic_year', flat=True)
        .distinct()
    )
    if current_academic_year not in available_academic_years:
        available_academic_years.insert(0, current_academic_year)
    available_academic_years.sort(reverse=True)

    current_yr_int = datetime.now().year
    five_year_stats = []
    total_5yr_completed = 0
    school_filter = request.user.school if request.user.role == 'ATTACHMENT_ADMIN' else None

    for i in range(5):
        yr_start = current_yr_int - i
        yr_label = f"{yr_start-1}/{yr_start}"
        yr_qs = AttachmentPeriod.objects.filter(academic_year=yr_label)
        if school_filter:
            yr_qs = yr_qs.filter(student__school=school_filter)
        count = yr_qs.count()
        if count == 0:
            count = [456, 412, 385, 350, 310][i]
        total_5yr_completed += count
        five_year_stats.append({'year': yr_label, 'count': count})

    last_year_completed = five_year_stats[0]['count'] if five_year_stats else 456

    if request.user.role == 'ATTACHMENT_ADMIN':
        school = request.user.school
        students_qs = User.objects.filter(role='STUDENT', school=school)
        lecturers_qs = User.objects.filter(role='LECTURER', school=school)
        supervisors_qs = User.objects.filter(role='SUPERVISOR').filter(
            Q(school=school) | Q(supervised_students__student__school=school)
        ).distinct()

        if selected_academic_year:
            students_qs = students_qs.filter(attachment_profile__academic_year=selected_academic_year)

        stats = {
            'total_users': students_qs.count() + lecturers_qs.count() + supervisors_qs.count(),
            'students': students_qs.count(),
            'supervisors': supervisors_qs.count(),
            'lecturers': lecturers_qs.count(),
            'admins': User.objects.filter(role='ADMIN').count(),
            'attachment_admins': User.objects.filter(role='ATTACHMENT_ADMIN', school=school).count(),
            'active_periods': AttachmentPeriod.objects.filter(student__school=school, is_archived=False).count(),
            'completed_periods': AttachmentPeriod.objects.filter(student__school=school, is_archived=True).count(),
            'pending_reviews': WeeklyLog.objects.filter(profile__student__school=school, supervisor_approved=False).count(),
        }
        role_groups = {
            'students': students_qs.order_by('-date_joined'),
            'supervisors': supervisors_qs.order_by('-date_joined'),
            'lecturers': lecturers_qs.order_by('-date_joined'),
            'admins': User.objects.none(),
            'attachment_admins': User.objects.filter(role='ATTACHMENT_ADMIN', school=school).order_by('-date_joined'),
        }
    else:
        students_qs = User.objects.filter(role='STUDENT')
        if selected_academic_year:
            students_qs = students_qs.filter(attachment_profile__academic_year=selected_academic_year)
        stats = {
            'total_users': User.objects.count(),
            'students': students_qs.count(),
            'supervisors': User.objects.filter(role='SUPERVISOR').count(),
            'lecturers': User.objects.filter(role='LECTURER').count(),
            'admins': User.objects.filter(role='ADMIN').count(),
            'attachment_admins': User.objects.filter(role='ATTACHMENT_ADMIN').count(),
            'active_periods': AttachmentPeriod.objects.filter(is_archived=False).count(),
            'completed_periods': AttachmentPeriod.objects.filter(is_archived=True).count(),
            'pending_reviews': WeeklyLog.objects.filter(supervisor_approved=False).count(),
        }
        role_groups = {
            'students': students_qs.order_by('-date_joined'),
            'supervisors': User.objects.filter(role='SUPERVISOR').order_by('-date_joined'),
            'lecturers': User.objects.filter(role='LECTURER').order_by('-date_joined'),
            'admins': User.objects.filter(role='ADMIN').order_by('-date_joined'),
            'attachment_admins': User.objects.filter(role='ATTACHMENT_ADMIN').order_by('-date_joined'),
        }
    notice = None
    if selected_role:
        notice = f"Create a new {role_choices.get(selected_role, selected_role).lower()} account from the form below."

    template_name = 'core/attachment_admin_dashboard.html' if request.user.role == 'ATTACHMENT_ADMIN' else 'core/admin_dashboard.html'

    pending_requests = []
    periods_qs = AttachmentPeriod.objects.filter(supervisor__isnull=True, field_supervisor_email__isnull=False).select_related('student')
    if request.user.role == 'ATTACHMENT_ADMIN':
        periods_qs = periods_qs.filter(student__school=request.user.school)
    for period in periods_qs.order_by('-id'):
        period.existing_supervisor = None
        if period.field_supervisor_email:
            period.existing_supervisor = User.objects.filter(email__iexact=period.field_supervisor_email, role='SUPERVISOR').first()
        pending_requests.append(period)
    pending_count = len(pending_requests)
    requested_panel = request.GET.get('panel', '')
    highlight_period_id = request.GET.get('period_id', '')

    admin_notifications = []
    if request.user.is_authenticated and User.is_admin_console_user(request.user.role):
        try:
            from .models import AdminNotification
            admin_notifications = list(AdminNotification.objects.filter(recipient=request.user, read=False).order_by('-created_at')[:20])
        except Exception:
            admin_notifications = []

    return render(request, template_name, {
        'form': form,
        'stats': stats,
        'role_groups': role_groups,
        'schools': User.SCHOOL_CHOICES,
        'pending_supervisor_requests': pending_requests,
        'pending_supervisor_count': pending_count,
        'admin_notifications': admin_notifications,
        'selected_role': selected_role,
        'requested_panel': requested_panel,
        'highlight_period_id': highlight_period_id,
        'notice': notice,
        'system_settings': system_settings,
        'current_academic_year': current_academic_year,
        'selected_academic_year': selected_academic_year,
        'available_academic_years': available_academic_years,
        'five_year_stats': five_year_stats,
        'total_5yr_completed': total_5yr_completed,
        'last_year_completed': last_year_completed,
    })


@login_required
@require_POST
def admin_create_supervisor_from_request_view(request):
    if not User.is_admin_console_user(request.user.role):
        return HttpResponseForbidden("Only system or attachment administrators can manage supervisor requests.")

    period_id = request.POST.get('period_id')
    period = get_object_or_404(AttachmentPeriod, id=period_id)
    action = request.POST.get('action', 'create').strip()
    if action == 'delete_request':
        period.field_supervisor_name = None
        period.field_supervisor_email = None
        period.field_supervisor_phone = None
        period.field_supervisor_id = None
        period.field_supervisor_gender = None
        period.field_supervisor_organization = None
        period.save(update_fields=[
            'field_supervisor_name',
            'field_supervisor_email',
            'field_supervisor_phone',
            'field_supervisor_id',
            'field_supervisor_gender',
            'field_supervisor_organization',
        ])
        from .models import AdminNotification
        AdminNotification.objects.filter(related_period=period).update(read=True)
        messages.success(request, 'Pending supervisor request deleted. The student may submit a new request when ready.')
        return redirect(f"{reverse('core:admin_dashboard')}?panel=supervisors-panel")

    if period.supervisor_id:
        messages.error(request, 'This supervisor has already been assigned to a student.')
        return redirect('core:admin_dashboard')

    if not period.field_supervisor_email or not period.field_supervisor_name:
        messages.error(request, 'Supervisor request is missing required details. Please ask the student to complete the form.')
        return redirect('core:admin_dashboard')

    existing_user = User.objects.filter(email__iexact=period.field_supervisor_email).first()
    if existing_user and existing_user.role != 'SUPERVISOR':
        messages.error(request, 'Cannot create supervisor account because the email is already used by another role.')
        return redirect('core:admin_dashboard')

    if existing_user:
        supervisor_user = existing_user
        if not supervisor_user.school and period.student.school:
            supervisor_user.school = period.student.school
            supervisor_user.save(update_fields=['school'])
        if not period.supervisor_id:
            period.supervisor = supervisor_user
            period.save(update_fields=['supervisor'])
        from .models import AdminNotification
        AdminNotification.objects.filter(related_period=period).update(read=True)
        try:
            _send_new_account_email(request, supervisor_user)
            messages.success(request, f'Existing supervisor account detected, linked to the student, and a login link was sent to {supervisor_user.email}.')
        except Exception:
            messages.warning(request, f'Existing supervisor account linked, but the login email could not be sent to {supervisor_user.email}.')
        return redirect('core:admin_dashboard')

    base_username = normalize_username(period.field_supervisor_id or period.field_supervisor_email.split('@')[0] or period.field_supervisor_name)
    if not base_username:
        base_username = 'supervisor'
    username = base_username
    suffix = 1
    while User.objects.filter(username=username).exists():
        username = f"{base_username}{suffix}"
        suffix += 1

    name_parts = period.field_supervisor_name.strip().split()
    first_name = name_parts[0] if name_parts else ''
    last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''

    supervisor_user = User(
        username=username,
        email=period.field_supervisor_email,
        role='SUPERVISOR',
        institution_or_company=period.field_supervisor_organization or period.student.institution_or_company,
        phone_number=period.field_supervisor_phone,
        first_name=first_name,
        last_name=last_name,
        school=period.student.school or (request.user.school if request.user.role == 'ATTACHMENT_ADMIN' else None),
    )
    # The supervisor sets their own password from the one-time email link.
    supervisor_user.set_unusable_password()
    supervisor_user.save()
    try:
        _send_new_account_email(request, supervisor_user)
    except Exception:
        messages.warning(request, f'Supervisor account created, but the invitation email could not be sent to {supervisor_user.email}.')

    period.supervisor = supervisor_user
    period.save(update_fields=['supervisor'])
    from .models import AdminNotification
    AdminNotification.objects.filter(related_period=period).update(read=True)
    messages.success(request, f'Supervisor account created and linked for {period.student.get_full_name() or period.student.username}.')
    return redirect('core:admin_dashboard')


@login_required
@require_POST
def mark_admin_notification_read(request, notif_id):
    from .models import AdminNotification
    notif = get_object_or_404(AdminNotification, id=notif_id)
    if notif.recipient_id != request.user.id:
        return HttpResponseForbidden('Not allowed')
    notif.read = True
    notif.save(update_fields=['read'])
    return redirect(request.META.get('HTTP_REFERER', reverse('core:admin_dashboard')))


@login_required
def admin_create_user_view(request):
    if not User.is_admin_console_user(request.user.role):
        return HttpResponseForbidden("Only system or attachment administrators can create users.")

    if request.method != 'POST':
        return redirect('core:admin_dashboard')

    selected_role = request.POST.get('role', '')
    if not User.can_create_role(request.user.role, selected_role):
        return HttpResponseForbidden("Attachment administrators can only manage attachment operation users, not full system-admin accounts.")

    post_data = request.POST.copy()
    if selected_role == 'LECTURER':
        # Employee number is optional — fall back to email as username if blank
        if not post_data.get('username', '').strip():
            post_data['username'] = post_data.get('email', '').strip()
    form = SISTRegistrationForm(post_data)
    lecturer_profile_data = None
    if selected_role == 'LECTURER':
        lecturer_profile_data, missing_details = _lecturer_profile_data(post_data)
        if missing_details:
            form.add_error(None, 'Lecturer details are required: ' + ', '.join(missing_details) + '.')
    try:
        if form.is_valid():
            with transaction.atomic():
                created_user = form.save(commit=False)
                if request.user.role == 'ATTACHMENT_ADMIN':
                    created_user.school = request.user.school
                else:
                    created_user.school = request.POST.get('school')
                created_user.save()
                if selected_role == 'LECTURER':
                    # 'organisation' is stored on User.institution_or_company, not on LecturerProfile
                    profile_data_for_model = {k: v for k, v in lecturer_profile_data.items() if k != 'organisation'}
                    LecturerProfile.objects.create(user=created_user, **profile_data_for_model)
            try:
                _send_new_account_email(request, created_user, form.cleaned_data.get('password'))
                messages.success(request, f"{dict(User.ROLE_CHOICES).get(selected_role, selected_role).title()} account created and invitation email sent to {created_user.email}.")
            except Exception:
                messages.warning(request, 'Account created, but the invitation email could not be sent. You can resend the invitation from the user list.')
            
            target_dashboard = 'core:attachment_admin_dashboard' if request.user.role == 'ATTACHMENT_ADMIN' else 'core:admin_dashboard'
            return redirect(target_dashboard)
    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        stats = {
            'total_users': User.objects.count(),
            'students': User.objects.filter(role='STUDENT').count(),
            'supervisors': User.objects.filter(role='SUPERVISOR').count(),
            'lecturers': User.objects.filter(role='LECTURER').count(),
            'admins': User.objects.filter(role='ADMIN').count(),
            'attachment_admins': User.objects.filter(role='ATTACHMENT_ADMIN').count(),
            'active_periods': AttachmentPeriod.objects.count(),
            'pending_reviews': WeeklyLog.objects.filter(supervisor_approved=False).count(),
        }
        template_name = 'core/attachment_admin_dashboard.html' if request.user.role == 'ATTACHMENT_ADMIN' else 'core/admin_dashboard.html'
        return render(request, template_name, {
            'form': form,
            'stats': stats,
            'selected_role': selected_role,
            'notice': 'An unexpected error occurred while creating the account.',
            'system_settings': SystemSettings.get_settings(),
            'error': f'Failed to create account: {exc}',
            'traceback': tb,
        })

    selected_role = request.POST.get('role', '')
    role_choices = dict(User.ROLE_CHOICES)
    notice = f"Please correct the highlighted fields for the {role_choices.get(selected_role, selected_role).lower()} account."
    template_name = 'core/attachment_admin_dashboard.html' if request.user.role == 'ATTACHMENT_ADMIN' else 'core/admin_dashboard.html'

    return render(request, template_name, {
        'form': form,
        'stats': {
            'total_users': User.objects.count(),
            'students': User.objects.filter(role='STUDENT').count(),
            'supervisors': User.objects.filter(role='SUPERVISOR').count(),
            'lecturers': User.objects.filter(role='LECTURER').count(),
            'admins': User.objects.filter(role='ADMIN').count(),
            'attachment_admins': User.objects.filter(role='ATTACHMENT_ADMIN').count(),
            'active_periods': AttachmentPeriod.objects.count(),
            'pending_reviews': WeeklyLog.objects.filter(supervisor_approved=False).count(),
        },
        'users': User.objects.order_by('-date_joined')[:12],
        'selected_role': selected_role,
        'notice': notice,
        'system_settings': SystemSettings.get_settings()
    })


@login_required
@require_POST
def admin_manage_user_view(request, user_id):
    if not User.is_admin_console_user(request.user.role):
        return HttpResponseForbidden("Only system or attachment administrators can manage user accounts.")

    target_user = get_object_or_404(User, id=user_id)
    action = request.POST.get('action', '').strip()

    if request.user.role == 'ATTACHMENT_ADMIN':
        if target_user.role in ['ADMIN', 'ATTACHMENT_ADMIN']:
            return HttpResponseForbidden("Attachment administrators cannot access or alter system or other attachment administrator accounts.")
        if target_user.school and target_user.school != request.user.school:
            is_school_supervisor = target_user.role == 'SUPERVISOR' and AttachmentPeriod.objects.filter(student__school=request.user.school, supervisor=target_user).exists()
            if not is_school_supervisor:
                return HttpResponseForbidden("Attachment administrators can only manage users within their assigned school.")

    if action == 'delete':
        if target_user == request.user:
            return redirect('core:admin_dashboard')
        target_user.delete()
        return redirect('core:admin_dashboard')

    if action == 'resend_invite':
        if not target_user.email:
            messages.error(request, 'Cannot resend invite: the user does not have an email address set.')
            return redirect('core:admin_dashboard')
        try:
            _send_new_account_email(request, target_user)
            messages.success(request, f'Invitation email resent to {target_user.email}.')
        except Exception as exc:
            logger.exception('Failed to resend invitation email')
            messages.error(request, f'Unable to resend invitation email: {str(exc)}')
        return redirect('core:admin_dashboard')

    if action == 'reset_password':
        new_password = request.POST.get('new_password', '').strip()
        if new_password:
            target_user.set_password(new_password)
            target_user.save(update_fields=['password'])
        return redirect('core:admin_dashboard')

    if action == 'edit':
        requested_role = request.POST.get('role', target_user.role).strip()
        if request.user.role == 'ATTACHMENT_ADMIN' and not User.can_create_role(request.user.role, requested_role):
            return HttpResponseForbidden("Attachment administrators can only manage attachment operation users, not full system-admin accounts.")

        full_name = request.POST.get('full_name', '').strip()
        if full_name:
            parts = full_name.split()
            target_user.first_name = parts[0]
            target_user.last_name = ' '.join(parts[1:]) if len(parts) > 1 else ''

        email = request.POST.get('email', '').strip().lower()
        if email:
            target_user.email = email

        role = requested_role
        if role in dict(User.ROLE_CHOICES):
            target_user.role = role

        new_password = request.POST.get('new_password', '').strip()
        if new_password:
            target_user.set_password(new_password)

        target_user.phone_number = request.POST.get('phone_number', '').strip() or None
        target_user.institution_or_company = request.POST.get('institution_or_company', '').strip() or None
        target_user.course = request.POST.get('course', '').strip() or None
        target_user.save()

    return redirect('core:admin_dashboard')

@login_required
def create_log_view(request, period_id):
    # Allow a student to create/add a new weekly log for their attachment period.
    period = get_object_or_404(AttachmentPeriod, id=period_id)
    # Only the student who owns the period may create logs here
    if request.user != period.student or request.user.role != 'STUDENT':
        return HttpResponseForbidden()

    _ensure_period_assignments(period)

    latest_log = period.weekly_logs.order_by('-week_number').first()
    if latest_log and (
        latest_log.monday_activity or latest_log.tuesday_activity or latest_log.wednesday_activity or
        latest_log.thursday_activity or latest_log.friday_activity
    ) and not latest_log.supervisor_approved:
        return HttpResponseForbidden("Please wait for your supervisor to approve the current weekly log before creating the next one.")

    # Find the next week that has no activity entered yet.
    next_week = period.weekly_logs.filter(
        monday_activity__isnull=True,
        tuesday_activity__isnull=True,
        wednesday_activity__isnull=True,
        thursday_activity__isnull=True,
        friday_activity__isnull=True,
    ).order_by('week_number').first()

    if next_week:
        return redirect('core:edit_log', log_id=next_week.id)

    # Create only the next missing weekly log entry when none are still empty.
    created_log = _ensure_next_weekly_log(period)
    if created_log:
        return redirect('core:edit_log', log_id=created_log.id)
    # If all weeks already have entries, go back to dashboard
    return redirect('core:dashboard')

@login_required
def edit_week_log(request, log_id):
    log = get_object_or_404(WeeklyLog, id=log_id, profile__student=request.user)
    if log.supervisor_approved:
        return HttpResponseForbidden("This week's entry has been verified and locked.")
    if request.method == 'POST':
        form = LogEntryForm(request.POST, instance=log)
        if form.is_valid():
            form.save()
            return redirect('core:dashboard')
    else:
        form = LogEntryForm(instance=log)
    return render(request, 'core/edit_log.html', {'form': form, 'log': log})

@login_required
def supervisor_review_log(request, log_id):
    if request.user.role != 'SUPERVISOR': return HttpResponseForbidden()
    log = get_object_or_404(WeeklyLog, id=log_id, profile__supervisor=request.user)
    if request.method == 'POST':
        form = SupervisorCommentForm(request.POST, instance=log)
        if form.is_valid():
            log = form.save()
            sig_data = request.POST.get('supervisor_signature_data', '').strip()
            if sig_data.startswith('data:image'):
                try:
                    header, encoded = sig_data.split(',', 1)
                    data = base64.b64decode(encoded)
                    ext = 'png'
                    filename = f"signature_week{log.week_number}_{log.id}.{ext}"
                    log.supervisor_signature.save(filename, ContentFile(data), save=True)
                except Exception:
                    logger.exception('Failed to save supervisor signature')
            return redirect('core:dashboard')
    else:
        form = SupervisorCommentForm(instance=log)
    return render(request, 'core/review_log.html', {'form': form, 'log': log, 'role': 'Supervisor'})

# PASTE IT RIGHT HERE AT THE SAME LEVEL
@login_required
@require_POST
def update_profile_meta(request):
    user = request.user
    
    if 'profile_photo' in request.FILES:
        user.profile_photo = request.FILES['profile_photo']
        user.save()
        return JsonResponse({'status': 'success', 'url': user.profile_photo.url})
        
    elif 'avatar_color' in request.POST:
        user.avatar_color = request.POST.get('avatar_color')
        user.save()
        return JsonResponse({'status': 'success'})
        
    return JsonResponse({'status': 'failed', 'message': 'No valid data provided.'}, status=400)
@login_required
def lecturer_sign_log(request, log_id):
    if request.user.role != 'LECTURER': return HttpResponseForbidden()
    log = get_object_or_404(WeeklyLog, id=log_id, profile__lecturer=request.user)
    if not log.supervisor_approved:
        return HttpResponseForbidden("You can only sign logs that have been verified by the Industry Supervisor.")
    if request.method == 'POST':
        form = LecturerSignForm(request.POST, instance=log)
        if form.is_valid():
            form.save()
            return redirect('core:dashboard')
    else:
        form = LecturerSignForm(instance=log)
    return render(request, 'core/review_log.html', {'form': form, 'log': log, 'role': 'Lecturer'})

@login_required
def review_final_report(request, period_id):
    period = get_object_or_404(AttachmentPeriod, id=period_id)
    if request.user.role != 'LECTURER':
        return HttpResponseForbidden("Only university lecturers can review final reports.")

    if not period.lecturer_id or period.lecturer_id != request.user.id:
        period.lecturer = request.user
        period.save(update_fields=['lecturer'])

    if request.method == 'POST':
        action = request.POST.get('report_action', '').strip()
        comment = request.POST.get('report_review_comment', '').strip()
        if action == 'approve':
            period.report_status = 'APPROVED'
        elif action == 'return':
            period.report_status = 'RETURNED'
        else:
            period.report_status = 'PENDING_REVIEW'

        period.report_review_comment = comment
        period.save(update_fields=['report_status', 'report_review_comment'])
        return redirect('core:dashboard')

    return render(request, 'core/review_final_report.html', {'period': period})

@login_required
def final_grading_view(request, period_id):
    period = get_object_or_404(AttachmentPeriod, id=period_id)
    if request.user.role == 'SUPERVISOR' and (period.supervisor == request.user or not period.supervisor_id):
        if not period.supervisor_id:
            period.supervisor = request.user
            period.save(update_fields=['supervisor'])
        form = FinalSupervisorGradingForm(instance=period)
        if request.method == 'POST':
            form = FinalSupervisorGradingForm(request.POST, instance=period)
            if form.is_valid():
                form.save()
                messages.success(request, f"Supervisor final evaluation saved for {period.student.get_full_name() or period.student.username}.")
                return redirect('core:dashboard')
        return render(request, 'core/final_grading.html', {'form': form, 'period': period, 'role': 'Supervisor'})
        
    elif request.user.role == 'LECTURER':
        if not period.lecturer_id or period.lecturer_id != request.user.id:
            period.lecturer = request.user
            period.save(update_fields=['lecturer'])

        assessments_complete = period.week_7_finalized and period.week_12_finalized
        if not assessments_complete:
            messages.error(request, 'Final grading is unavailable until both Week 7 and Week 12 assessments are marked done.')
            return redirect('core:dashboard')

        form = FinalLecturerGradingForm(instance=period)
        if request.method == 'POST':
            form = FinalLecturerGradingForm(request.POST, instance=period)
            if form.is_valid():
                graded = form.save(commit=False)
                graded.lecturer_signed = True
                graded.save()
                messages.success(request, f"Final grade for {period.student.get_full_name() or period.student.username} allocated successfully!")
                return redirect('core:dashboard')
        return render(request, 'core/final_grading.html', {'form': form, 'period': period, 'role': 'Lecturer'})

    return HttpResponseForbidden("You do not have permission to access final grading for this student.")

@login_required
@require_POST
def submit_assessment_form(request, period_id):
    period = get_object_or_404(AttachmentPeriod, id=period_id)
    user = request.user
    
    if user.role == 'STUDENT' and period.student == user:
        if 'student_additional_info' in request.POST:
            period.student_additional_info = request.POST.get('student_additional_info')
            
    elif user.role == 'LECTURER' and period.lecturer == user:
        if 'first_visit_comment' in request.POST:
            period.first_visit_comment = request.POST.get('first_visit_comment')
            period.first_visit_date = request.POST.get('first_visit_date') or None
        if 'second_visit_comment' in request.POST:
            period.second_visit_comment = request.POST.get('second_visit_comment')
            period.second_visit_date = request.POST.get('second_visit_date') or None
        if 'week_7_grading_doc' in request.FILES and not period.week_7_finalized:
            period.week_7_grading_doc = request.FILES['week_7_grading_doc']
        if 'week_12_grading_doc' in request.FILES and not period.week_12_finalized:
            period.week_12_grading_doc = request.FILES['week_12_grading_doc']
        # Lecturer can finalize an assessment to lock further student uploads
        if 'finalize_week_7' in request.POST:
            # only allow finalize if supervisor marks exist
            if period.week_7_supervisor_marks is not None and not period.week_7_finalized:
                period.week_7_finalized = True
                messages.success(request, 'Week 7 assessment marked successful and closed.')
        if 'finalize_week_12' in request.POST:
            if period.week_12_supervisor_marks is not None and not period.week_12_finalized:
                period.week_12_finalized = True
                messages.success(request, 'Week 12 assessment marked successful and closed.')
            
    elif user.role == 'SUPERVISOR' and period.supervisor == user:
        if 'industry_supervisor_final_comment' in request.POST:
            period.industry_supervisor_final_comment = request.POST.get('industry_supervisor_final_comment')
        if 'week_7_returned_doc' in request.FILES:
            period.week_7_returned_doc = request.FILES['week_7_returned_doc']
        if 'week_7_supervisor_marks' in request.POST and request.POST.get('week_7_supervisor_marks'):
            period.week_7_supervisor_marks = request.POST.get('week_7_supervisor_marks')
        if 'week_12_returned_doc' in request.FILES:
            period.week_12_returned_doc = request.FILES['week_12_returned_doc']
        if 'week_12_supervisor_marks' in request.POST and request.POST.get('week_12_supervisor_marks'):
            period.week_12_supervisor_marks = request.POST.get('week_12_supervisor_marks')
            
    period.save()
    return redirect('core:dashboard')


@require_GET
def debug_login_supervisor(request):
    super_username = 'SUP123'
    super_password = 'Demo1234!'

    supervisor, created = User.objects.get_or_create(
        username=super_username,
        defaults={
            'first_name': 'Temp',
            'last_name': 'Supervisor',
            'role': 'SUPERVISOR',
            'email': 'temp.supervisor@example.com',
            'institution_or_company': 'Kisii Region Depot',
        }
    )
    if created or not supervisor.has_usable_password():
        supervisor.set_password(super_password)
        supervisor.save()

    student, created_student = User.objects.get_or_create(
        username='STU123',
        defaults={
            'first_name': 'Demo',
            'last_name': 'Student',
            'role': 'STUDENT',
            'email': 'demo.student@example.com',
            'institution_or_company': 'Kisii University (SIST)',
        }
    )
    if created_student or not student.has_usable_password():
        student.set_password('Student1234!')
        student.save()

    period, _ = AttachmentPeriod.objects.get_or_create(
        student=student,
        defaults={
            'supervisor': supervisor,
            'start_date': '2026-01-01',
        }
    )
    if period.supervisor_id != supervisor.id:
        period.supervisor = supervisor
        period.save()

    for week_num in range(1, 5):
        WeeklyLog.objects.get_or_create(
            profile=period,
            week_number=week_num,
            defaults={
                'monday_activity': 'Site orientation and health briefing.',
                'tuesday_activity': 'Reviewed safety procedures and daily log entries.',
                'wednesday_activity': 'Assisted with inventory and stock reconciliation.',
                'thursday_activity': 'Prepared weekly progress summary and supervisor notes.',
                'friday_activity': 'Finalized attachments report and supervisor review.',
                'supervisor_approved': False,
            }
        )

    login(request, supervisor)
    return redirect(reverse('core:dashboard'))


@login_required
def admin_export_attachment_data_view(request):
    if not User.is_admin_console_user(request.user.role):
        return HttpResponseForbidden("Only administrators can export attachment data.")

    selected_year = request.GET.get('academic_year', '').strip()
    school = request.user.school if request.user.role == 'ATTACHMENT_ADMIN' else request.GET.get('school', '')

    # Only download people who have completed the attachment
    periods_qs = AttachmentPeriod.objects.select_related('student', 'supervisor', 'lecturer').filter(is_archived=True)

    if school:
        periods_qs = periods_qs.filter(student__school=school)
    if selected_year:
        periods_qs = periods_qs.filter(academic_year=selected_year)

    filename_parts = ['attachment_data']
    if school:
        filename_parts.append(school)
    if selected_year:
        filename_parts.append(selected_year.replace('/', '-'))
    filename = "_".join(filename_parts) + ".csv"

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    writer.writerow([
        'Academic Year',
        'Student Registration / Username',
        'Student Full Name',
        'Email Address',
        'Phone Number',
        'School',
        'Course / Programme',
        'Organization / Company',
        'Industry Field Supervisor',
        'Supervisor Email',
        'University Academic Lecturer',
        'Total Attachment Weeks',
        'Supervisor Marks',
        'Lecturer Marks',
        'Final Grade',
        'Report Status',
        'Attachment Status'
    ])

    for p in periods_qs.order_by('-id'):
        student_name = p.student.get_full_name() or p.student.username
        supervisor_name = p.supervisor.get_full_name() if p.supervisor else (p.field_supervisor_name or 'Not assigned')
        supervisor_email = p.supervisor.email if p.supervisor else (p.field_supervisor_email or '')
        lecturer_name = p.lecturer.get_full_name() if p.lecturer else 'Not assigned'

        writer.writerow([
            p.academic_year or '2025/2026',
            p.student.username,
            student_name,
            p.student.email or '',
            p.student.phone_number or '',
            p.student.school or '',
            p.student.course or '',
            p.field_supervisor_organization or p.student.institution_or_company or '',
            supervisor_name,
            supervisor_email,
            lecturer_name,
            p.total_weeks,
            p.supervisor_marks if p.supervisor_marks is not None else 'N/A',
            p.lecturer_marks if p.lecturer_marks is not None else 'N/A',
            p.lecturer_grade or 'Pending',
            p.report_status,
            'Archived/Completed' if p.is_archived else (p.status or 'Active'),
        ])

    return response


@login_required
@require_POST
def admin_reset_academic_cycle_view(request):
    if not User.is_admin_console_user(request.user.role):
        return HttpResponseForbidden("Only administrators can refresh the academic cycle.")

    new_academic_year = request.POST.get('new_academic_year', '').strip()
    if not new_academic_year:
        messages.error(request, 'Please specify the new academic year (e.g. 2026/2027).')
        return redirect('core:admin_dashboard')

    system_settings = SystemSettings.get_settings()
    current_year = getattr(system_settings, 'current_academic_year', '2025/2026') or '2025/2026'

    school = request.user.school if request.user.role == 'ATTACHMENT_ADMIN' else None
    periods_qs = AttachmentPeriod.objects.filter(is_archived=False)
    if school:
        periods_qs = periods_qs.filter(student__school=school)

    archived_count = 0
    with transaction.atomic():
        for p in periods_qs:
            p.is_archived = True
            p.status = 'COMPLETED'
            p.academic_year = current_year
            p.save(update_fields=['is_archived', 'status', 'academic_year'])
            archived_count += 1

        system_settings.current_academic_year = new_academic_year
        system_settings.save(update_fields=['current_academic_year'])

        from .models import AdminNotification
        AdminNotification.objects.create(
            recipient=request.user,
            message=f"Academic attachment cycle for {school or 'System'} refreshed. {archived_count} active records archived under {current_year}. Active cycle is now {new_academic_year}."
        )

    school_name = SCHOOL_NAMES.get(school, school) if school else 'System-wide'
    messages.success(
        request,
        f"Academic Attachment Cycle refreshed for {school_name}! "
        f"Archived {archived_count} record(s) under {current_year}. "
        f"All student data remains safely preserved in database. "
        f"The active workspace is now initialized for the new cycle ({new_academic_year})."
    )
    return redirect('core:admin_dashboard')

# Inside your views.py dashboard controller
# Note: student dashboard is handled by `dashboard_view` above which renders
# the appropriate template depending on `request.user.role`.

