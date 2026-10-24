import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_JadeFlare {
    private static boolean privateTrue = true;

    private void queryJadeFlare(String data) throws SQLException {
        Connection jadeFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeFlare");
        Statement jadeFlareStatement = null;
        ResultSet jadeFlareRows = null;
        try {
            jadeFlareStatement = jadeFlareConnection.createStatement();
            jadeFlareRows = jadeFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeFlareRows.getRow());
        } finally {
            if (jadeFlareRows != null) {
                jadeFlareRows.close();
            }
            if (jadeFlareStatement != null) {
                jadeFlareStatement.close();
            }
            jadeFlareConnection.close();
        }
    }

    public void runJadeFlare() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("JADE_FLARE_FILTER");
        } else {
            data = null;
        }
        queryJadeFlare(data);
    }
}
