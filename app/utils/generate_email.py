from jinja2 import Environment, FileSystemLoader


def generate_html_email(name, title, text):
    # Cargar las plantillas desde el directorio de plantillas
    env = Environment(loader=FileSystemLoader('utils/templates'))
    template = env.get_template('email_template.html')

    # Renderizar la plantilla con los datos
    html_content = template.render(name=name, title=title, text=text)
    return html_content
