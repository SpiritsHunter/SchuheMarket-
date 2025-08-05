public class DidadasSchuhfabrik implements Schuhfabrik {

    @java.lang.Override
    public void createSchuhe() {
        new SportschuheDidadas();
        new WanderSchuheDidadas();
        new StiefelDidadas();
    }
}
