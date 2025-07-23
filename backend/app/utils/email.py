
from jinja2 import FileSystemLoader, select_autoescape, Environment

env = Environment(
    loader=FileSystemLoader("frontend/templates"),
    autoescape=select_autoescape(['html', 'xml'])
)

def render_email_template(template_name: str, context: dict):
    template = env.get_template(template_name)
    return template.render(context)