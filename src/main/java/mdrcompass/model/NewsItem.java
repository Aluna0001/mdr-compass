package mdrcompass.model;

public class NewsItem {

    private String title;
    private String link;
    private String pubDate;

    public NewsItem(String title, String link, String pubDate) {
        this.title = title;
        this.link = link;
        this.pubDate = pubDate;
    }

    public String getTitle() {
        return title;
    }

    public String getLink() {
        return link;
    }

    public String getPubDate() {
        return pubDate;
    }
}