public class EnkiSchuhfabrik implements Schuhfabrik {

    @java.lang.Override
    public void createSchuhe() {
        new SportschuheEnki();
        new WanderSchuheEnki();
        new StiefelEnki();
    }
}
