public class UmapSchuhfabrik implements Schuhfabrik {

    @java.lang.Override
    public void createSchuhe() {
        new SportschuheUmap();
        new WanderSchuheUmap();
        new StiefelUmap();
    }
}
