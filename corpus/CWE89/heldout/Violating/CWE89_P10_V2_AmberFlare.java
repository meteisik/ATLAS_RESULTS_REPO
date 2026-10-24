import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberFlare {

    public static String data;

    public void runAmberFlare() throws SQLException {
        if (5 == 5) {
            data = System.getenv("AMBER_FLARE_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AmberFlareSink()).queryAmberFlare();
    }
}

class CWE89_P10_V2_AmberFlareSink {
    public void queryAmberFlare() throws SQLException {
        String data = CWE89_P10_V2_AmberFlare.data;
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
