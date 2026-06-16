package mdrcompass.service;

import mdrcompass.model.NewsItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class NewsService {

    private static final Logger logger = LoggerFactory.getLogger(NewsService.class);
    private static final String FEED_URL = "https://feeds.feedburner.com/TheHackersNews";
    private static final int MAX_ITEMS = 15;
    private static final Duration CACHE_TTL = Duration.ofMinutes(15);

    private final HttpClient httpClient = HttpClient.newHttpClient();

    private List<NewsItem> cachedItems = new ArrayList<>();
    private Instant lastFetch = Instant.EPOCH;

    public List<NewsItem> getNews() {
        if (Instant.now().isBefore(lastFetch.plus(CACHE_TTL)) && !cachedItems.isEmpty()) {
            return cachedItems;
        }
        try {
            List<NewsItem> items = fetchAndParse();
            cachedItems = items;
            lastFetch = Instant.now();
            return items;
        } catch (Exception e) {
            logger.warn("Failed to fetch news feed: {}", e.getMessage());
            return cachedItems;
        }
    }

    private List<NewsItem> fetchAndParse() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(FEED_URL))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

        HttpResponse<InputStream> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofInputStream());

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        //security setup
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(response.body());

        NodeList itemNodes = doc.getElementsByTagName("item");
        List<NewsItem> items = new ArrayList<>();

        for (int i = 0; i < itemNodes.getLength() && items.size() < MAX_ITEMS; i++) {
            Node node = itemNodes.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element) node;
                String title = getTagValue(element, "title");
                String link = getTagValue(element, "link");
                String pubDate = getTagValue(element, "pubDate");
                items.add(new NewsItem(title, link, pubDate));
            }
        }
        return items;
    }

    private String getTagValue(Element element, String tag) {
        NodeList nodes = element.getElementsByTagName(tag);
        if (nodes.getLength() > 0 && nodes.item(0).getTextContent() != null) {
            return nodes.item(0).getTextContent().trim();
        }
        return "";
    }
}