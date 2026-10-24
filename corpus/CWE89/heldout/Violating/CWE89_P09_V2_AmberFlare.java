import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberFlare {

    static class Container {
        public String containerOne;
    }

    public void runAmberFlare() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_FLARE_FILTER");
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberFlareSink()).queryAmberFlare(dataContainer);
    }
}

class CWE89_P09_V2_AmberFlareSink {
    public void queryAmberFlare(CWE89_P09_V2_AmberFlare.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection amberFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberFlare");
        Statement amberFlareStatement = null;
        ResultSet amberFlareRows = null;
        try {
            amberFlareStatement = amberFlareConnection.createStatement();
            amberFlareRows = amberFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberFlareRows.getRow());
        } finally {
            if (amberFlareRows != null) {
                amberFlareRows.close();
            }
            if (amberFlareStatement != null) {
                amberFlareStatement.close();
            }
            amberFlareConnection.close();
        }
    }
}
