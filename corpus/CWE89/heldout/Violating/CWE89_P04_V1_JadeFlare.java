import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_JadeFlare {

    private String loadJadeFlare() {
        String data;
        data = System.getenv("JADE_FLARE_FILTER");
        return data;
    }

    public void runJadeFlare() throws SQLException {
        String data = loadJadeFlare();
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
}
