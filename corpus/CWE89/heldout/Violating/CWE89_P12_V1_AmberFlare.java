import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberFlare {

    public void runAmberFlare() throws SQLException {
        String data;
        data = System.getenv("AMBER_FLARE_FILTER");
        CWE89_P12_V1_AmberFlareBase baseObject = new CWE89_P12_V1_AmberFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberFlareBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberFlareSink extends CWE89_P12_V1_AmberFlareBase {
    public void action(String data) throws SQLException {
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
