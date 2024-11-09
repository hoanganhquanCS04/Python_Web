from django.shortcuts import render
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from .models import SearchHistory, Material, VideoLecture  # Import models from 'search'
import unidecode  # Thư viện để chuyển đổi tiếng Việt có dấu thành không dấu
from fuzzywuzzy import process  # Thư viện để tìm gợi ý từ khóa

@login_required  
def search(request):
    query = request.GET.get('q', '').strip()
    content_type = request.GET.get('content_type', 'all')  # Lấy loại nội dung (tài liệu, video)
    page_number = request.GET.get('page', 1)
    no_results_message = None
    suggestion = None

    # Nếu không có từ khóa tìm kiếm, trả về trang kết quả rỗng
    if not query:
        return render(request, 'search/search_results.html', {
            'results': {}, 
            'query': query,
            'content_type': content_type
        })

    # Chuyển từ khóa thành dạng không dấu để tìm kiếm tiếng Việt không dấu
    query_no_diacritics = unidecode.unidecode(query)

    # Tìm kiếm trên nhiều trường của các model
    materials = Material.objects.filter(
        Q(title__icontains=query) | Q(description__icontains=query) |
        Q(title__icontains=query_no_diacritics) | Q(description__icontains=query_no_diacritics)
    )
    videos = VideoLecture.objects.filter(
        Q(video_name__icontains=query) | Q(subject__subject_name__icontains=query) | Q(description__icontains=query) |
        Q(video_name__icontains=query_no_diacritics) | Q(subject__subject_name__icontains=query_no_diacritics) | Q(description__icontains=query_no_diacritics)
    )

    # Nếu không tìm thấy bất kỳ kết quả nào, tìm gợi ý từ khóa gần đúng nhất
    if not materials.exists() and not videos.exists():
        all_titles = [m.title for m in Material.objects.all()] + [v.video_name for v in VideoLecture.objects.all()]
        closest_match = process.extractOne(query, all_titles)
        if closest_match and closest_match[1] >= 60:  # Ngưỡng độ chính xác cho gợi ý
            suggestion = closest_match[0]
            no_results_message = f"Không có dữ liệu nào phù hợp với từ khóa '{query}'. Gợi ý: bạn có muốn tìm '{suggestion}' không?"
        else:
            no_results_message = f"Không có dữ liệu nào phù hợp với từ khóa '{query}'."
        return render(request, 'search/search_results.html', {
            'results': None,
            'query': query,
            'content_type': content_type,
            'no_results_message': no_results_message,
            'suggestion': suggestion,
        })

    # Lưu lịch sử tìm kiếm nếu tìm thấy kết quả
    if materials.exists() or videos.exists():
        SearchHistory.objects.create(user=request.user, query=query)

    # Tổng hợp và phân trang kết quả
    results = list(materials) + list(videos)

    paginator = Paginator(results, 15)  # Tổng hợp các loại nội dung với 15 kết quả mỗi trang
    page_obj = paginator.get_page(page_number)

    return render(request, 'search/search_results.html', {
        'results': page_obj,
        'query': query,
        'content_type': content_type,
        'no_results_message': no_results_message,
        'suggestion': suggestion,
    })

@login_required
def search_history(request):
    # Lấy lịch sử tìm kiếm của người dùng hiện tại và sắp xếp theo thời gian mới nhất
    history = SearchHistory.objects.filter(user=request.user).order_by('-timestamp')
    return render(request, 'search/search_history.html', {'history': history})
