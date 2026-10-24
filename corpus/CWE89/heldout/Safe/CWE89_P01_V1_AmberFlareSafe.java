import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_AmberFlareSafe {

    public void runAmberFlare() throws SQLException {
        String data;
        data = "foo";
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
