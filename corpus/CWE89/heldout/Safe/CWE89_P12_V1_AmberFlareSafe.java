import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberFlareSafe {

    public void runAmberFlare() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberFlareSafeBase baseObject = new CWE89_P12_V1_AmberFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberFlareSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberFlareSafeSink extends CWE89_P12_V1_AmberFlareSafeBase {
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
