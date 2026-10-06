"""Build an offline Plotly 3D point view and clarify the notebook's validity scope."""
import argparse
import base64
import hashlib
import html
import json
from pathlib import Path


def verify_projection(p,nb,report,explanation_raw):
    explanation=json.loads(explanation_raw)
    if hashlib.sha256(explanation_raw).hexdigest()!=nb['metadata']['cluster_explanation_sha256']:
        raise ValueError('pinned cluster explanation changed')
    if p['training_complete_sha256']!=explanation['training_complete_sha256']:
        raise ValueError('3D projection belongs to a different frozen model revision')
    expected=[report['compositions'][d]['seal']['bundle_sha256'] for d in ('day22','day28')]
    if p['source_identity']!=report['training']['source_identity'] or p['source_identity']!=explanation['source_identity'] or p['sealed_bundle_sha256']!=expected or explanation['sealed_bundle_sha256']!=expected:
        raise ValueError('3D projection belongs to different training source')


def make_figure(p):
    import plotly.graph_objects as go
    colors=['#718096','#3182ce','#38a169','#e53e3e','#805ad5','#dd6b20','#d53f8c','#0891b2']
    role_labels={'unlabelled_office':'Офис без метки','matched_control':'Обычный контроль','observed_positive':'Сценарий','hard_negative':'Сложный отрицательный'}
    pts=p['points'];traces=[]
    for cluster in range(8):
        selected=[r for r in pts if r[3]==cluster]
        traces.append(go.Scatter3d(x=[r[0] for r in selected],y=[r[1] for r in selected],z=[r[2] for r in selected],
            mode='markers',name=f'C{cluster} · n={len(selected)}',marker={'size':2,'color':colors[cluster],'opacity':.65},
            customdata=[[role_labels[r[6]],r[5]] for r in selected],
            hovertemplate=f'C{cluster}<br>%{{customdata[0]}} · %{{customdata[1]}}<br>PC1=%{{x:.3f}} PC2=%{{y:.3f}} PC3=%{{z:.3f}}<extra></extra>'))
    for role,color in zip(role_labels,['#718096','#3182ce','#e76f51','#9f7aea']):
        selected=[r for r in pts if r[6]==role]
        traces.append(go.Scatter3d(x=[r[0] for r in selected],y=[r[1] for r in selected],z=[r[2] for r in selected],
            mode='markers',name=f'{role_labels[role]} · n={len(selected)}',visible=False,
            marker={'size':2,'color':color,'opacity':.65},customdata=[[r[3],r[5]] for r in selected],
            hovertemplate='C%{customdata[0]} · %{customdata[1]}<br>PC1=%{x:.3f} PC2=%{y:.3f} PC3=%{z:.3f}<extra>'+role_labels[role]+'</extra>'))
    centers=p['cluster_centers_3d'];traces.append(go.Scatter3d(x=[r[0] for r in centers],y=[r[1] for r in centers],z=[r[2] for r in centers],
        mode='markers+text',text=[f'C{i}' for i in range(8)],textposition='top center',name='Центры KMeans',
        marker={'size':5,'color':'#111827','symbol':'diamond'},hoverinfo='text'))
    var=p['explained_variance_ratio'];scene={'aspectmode':'cube','camera':{'eye':{'x':1.5,'y':1.5,'z':1.15}}}
    for i,axis in enumerate(['xaxis','yaxis','zaxis']):scene[axis]={'title':f'PC{i+1} · {var[i]:.1%} дисперсии','range':p['zoom_ranges'][i]}
    title=f'Основные скопления: {p["zoom_visible_rows"]} / {len(pts)} точек; вне кадра {p["zoom_outside_rows"]}'
    fig=go.Figure(traces);fig.update_layout(height=730,margin={'l':0,'r':0,'t':105,'b':0},scene=scene,template='plotly_white',
        title={'text':title,'font':{'size':16}},legend={'font':{'size':11}},
        updatemenus=[{'type':'buttons','direction':'right','x':0,'y':1.10,'buttons':[
            {'label':'Цвет: кластер','method':'update','args':[{'visible':[True]*8+[False]*4+[True]}]},
            {'label':'Цвет: происхождение / роль','method':'update','args':[{'visible':[False]*8+[True]*4+[True]}]}]},
            {'type':'buttons','direction':'right','x':0,'y':1.04,'buttons':[
                {'label':'Основные скопления','method':'relayout','args':[{'scene.xaxis.autorange':False,'scene.yaxis.autorange':False,'scene.zaxis.autorange':False,'scene.xaxis.range':p['zoom_ranges'][0],'scene.yaxis.range':p['zoom_ranges'][1],'scene.zaxis.range':p['zoom_ranges'][2],'title.text':title}]},
                {'label':'Все точки + выбросы','method':'relayout','args':[{'scene.xaxis.autorange':True,'scene.yaxis.autorange':True,'scene.zaxis.autorange':True,'title.text':f'Полный диапазон: {len(pts)} точек, включая редкие выбросы'}]}]}])
    return fig


def add(notebook,projection,out_html,out_png):
    import plotly.io as pio
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    p=json.loads(Path(projection).read_text());nbpath=Path(notebook);nb=json.loads(nbpath.read_text())
    report=next(Path(notebook).resolve().parents[1].glob('reports/cover_channels_research_20261004.json'))
    r=json.loads(report.read_text());m=r['training']
    verify_projection(p,nb,r,(report.parent/'cover_channels_clusters_20261004.json').read_bytes())
    fig=make_figure(p);document=pio.to_html(fig,include_plotlyjs=True,full_html=True,config={'displaylogo':False,'responsive':True})
    Path(out_html).write_text(document)
    # An embedded static fallback remains readable in viewers that block HTML.
    colors=['#718096','#3182ce','#38a169','#e53e3e','#805ad5','#dd6b20','#d53f8c','#0891b2']
    static=plt.figure(figsize=(10,8),layout='constrained');ax=static.add_subplot(111,projection='3d')
    for cluster in range(8):
        selected=[row for row in p['points'] if row[3]==cluster and all(lo<=row[i]<=hi for i,(lo,hi) in enumerate(p['zoom_ranges']))]
        if selected:ax.scatter([row[0] for row in selected],[row[1] for row in selected],[row[2] for row in selected],s=3,alpha=.4,color=colors[cluster],label=f'C{cluster}')
    for i,axis in enumerate(['x','y','z']):getattr(ax,'set_'+axis+'lim')(*p['zoom_ranges'][i]);getattr(ax,'set_'+axis+'label')(f'PC{i+1} · {p["explained_variance_ratio"][i]:.1%}')
    ax.set_title(f'3D-проекция основных скоплений · {p["zoom_visible_rows"]}/{len(p["points"])} сегментов');ax.legend(loc='upper left');ax.view_init(elev=23,azim=38)
    static.savefig(out_png,dpi=150);plt.close(static)
    nb['cells']=[c for c in nb['cells'] if not c.get('id','').startswith('three-d-')];cells=[]
    def md(text,attachment=False):
        c={'cell_type':'markdown','id':f'three-d-{len(cells)}','metadata':{},'source':text.splitlines(keepends=True)}
        if attachment:c['attachments']={'cluster_3d.png':{'image/png':base64.b64encode(Path(out_png).read_bytes()).decode()}}
        cells.append(c)
    ratio=sum(p['explained_variance_ratio'][:3]);pin=hashlib.sha256(Path(projection).read_bytes()).hexdigest()
    md(f'''## 7. Точки в 3D: скопления кластеров

Каждая точка — один сегмент трафика. Здесь все {len(p['points']):,} размеченных и офисных записей исследовательского экспорта; дополнительного прореживания нет. Офис представлен сохранённой reservoir-выборкой из10 000 сегментов, не всеми офисными пакетами.

Мышью вращайте график, колёсиком меняйте масштаб. Кнопки переключают цвет между кластером и происхождением/ролью. В увеличенном виде видно {p['zoom_visible_rows']} точек, за рамкой {p['zoom_outside_rows']}; кнопка «Все точки + выбросы» показывает полный диапазон. Наведение показывает роль и split без адресов или ID.

PC1–PC3 объясняют **{ratio:.1%} дисперсии**. Кластеры рассчитаны в {p['clustering_dimensions']} измерениях, поэтому пересечение облаков в3D не означает одинаковые группы. Оси — смеси признаков, не время/объём/вредоносность. Точки не перемещались вручную для красивого разделения.

[Открыть автономный интерактивный график](../reports/{Path(out_html).name}) — работает без сервера и сети. Ниже встроен тот же график; просмотр HTML в Jupyter может потребовать доверия к ноутбуку.
''')
    escaped=html.escape(document,quote=True);output='<iframe title="3D кластеры" style="width:100%;height:780px;border:0" sandbox="allow-scripts" srcdoc="'+escaped+'"></iframe>'
    code='''from pathlib import Path
html_path = next((q / "workspace/reports/cover_channels_clusters_3d_20261004.html"
                  for q in [Path.cwd(), *Path.cwd().parents]
                  if (q / "workspace/reports/cover_channels_clusters_3d_20261004.html").is_file()), None)
if html_path is None:
    print("Используйте сохранённый вывод или ссылку на автономный HTML выше.")
else:
    try:
        from IPython.display import HTML, display
    except ImportError:
        print("Автономный интерактивный график:", html_path)
    else:
        import html
        display(HTML('<iframe style="width:100%;height:780px;border:0" sandbox="allow-scripts" srcdoc="'
                     + html.escape(html_path.read_text(), quote=True) + '"></iframe>'))
'''
    cells.append({'cell_type':'code','id':f'three-d-{len(cells)}','metadata':{},'source':code.splitlines(keepends=True),'execution_count':5,
        'outputs':[{'output_type':'display_data','data':{'text/html':[output],'text/plain':['Интерактивная 3D-проекция']},'metadata':{}}]})
    md('Статический вид для редакторов, которые не отображают интерактивный HTML:\n\n![3D скопления](attachment:cluster_3d.png)',True)
    md(f'''## 8. Как именно сделана кластеризация

1. **Одна строка — один сегмент сетевой сессии.** Исходных измерений {p['input_features']}; адреса, порты, ID, метки и названия механик в X не входят.
2. **Определена обучающая часть:** {p['fit_rows']:,} строк — профили train и офисная выборка22 сентября. Офис28 сентября и test-профили используются только для проверки.
3. **Удалены пустые и постоянные на train признаки:** осталось {p['used_features']}. Для остальных пропуски заполняются медианой train.
4. **Масштабы выровнены:** StandardScaler вычитает train-среднее и делит на train-стандартное отклонение. Иначе байты могли бы подавить интервалы времени просто из-за единиц измерения.
5. **PCA сжимает признаки до {p['clustering_dimensions']} линейных компонент.** Она сохраняет направления с большой дисперсией; не использует метки скрытого канала. Для картинки показаны первые3.
6. **KMeans ищет8 центров** и минимизирует сумму квадратов расстояний до ближайшего центра. Использовано20 инициализаций и фиксированный seed. k=8 задан для исследования, оптимальность числа кластеров не доказана.
7. **Новые записи получают ближайший сохранённый центр.** Только после этого мы смотрим, какие роли и механики попали внутрь каждой группы.

Поэтому кластеры отражают похожую форму измеренного трафика, а не автоматически «8 типов скрытых каналов». PCA и KMeans чувствительны к экстремальным значениям: редкие C3/C4/C7 — одна из причин осторожной интерпретации.
''')
    md('''## 9. Что проверено для обучения, а что — для естественности

**Техническая пригодность проверена:** источник и захваты закреплены хешами; обмен подтверждён наблюдениями; учёт добавленных пакетов согласован с метками; X и y совпадают по строкам; исходные офисные сегменты сохранены; обе роли и все размещения одного профиля целиком остаются в одном split. Неизвестный офис не объявляется безопасным. Это позволяет обучать исследовательскую модель и интерпретировать её ограничения.

**Естественность проверяется отдельно:**

| Проверка | Что измеряет | Результат |
|---|---|---|
| Сохранность офисного фона | Не испортило ли смешивание уже существующие офисные сессии | Проверка пройдена; это не доказывает реалистичность добавлений |
| Парные условия и временные подтверждения | Сопоставимость сценария/контроля и воспроизведение источника | Общие условия внутри пары;20 arms ускорены1000×; некоторые механики source-specific |
| Train-отбор признаков | Есть ли полезный сигнал без сильного отличия от офиса в одном признаке | Требовались scenario/control AUC>0.60, origin AUC≤0.60 и missing gap≤0.10; прошедших признаков0 |
| Origin-модель на holdout | Узнаётся ли стенд даже по сочетанию признаков | ROC AUC1.000: происхождение очень легко различается |
| Состав кластеров на holdout | Смешиваются ли офис и генератор в группах | Иногда смешиваются; это слабая описательная проверка, не доказательство естественности |

**Вывод: срез технически валиден для исследовательского обучения, но естественность добавлений не подтверждена.** Нельзя трактовать AUC0.697 сценарий/контроль как качество офисного детектора или заявлять, что модель смотрит только на решающие реальные признаки. Порог на такой модели не устраняет происхождение.

Совпадение распределений нескольких признаков и красивые облака были бы лишь частью проверки. Сильное подтверждение потребует независимых реальных офисных позитивов и проверки на других клиентах/серверах/днях. Добавление стендового обмена к сохранённому фону не воспроизводит взаимодействие с офисными middleboxes и конкуренцию за сеть.
''')
    md(f'Проекция воспроизведена сохранённой моделью; обучение не менялось. SHA256 координат: `{pin}`. Перенесены только округлённые PCA-координаты, cluster/split/role; исходные офисные признаки, адреса, payload и ID не экспортированы.')
    nb['cells'].extend(cells);nb['metadata']['projection3d_sha256']=pin
    nbpath.write_text(json.dumps(nb,ensure_ascii=False,indent=1)+'\n')
    return fig


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('notebook','projection','out-html','out-png'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();add(a.notebook,a.projection,a.out_html,a.out_png)
