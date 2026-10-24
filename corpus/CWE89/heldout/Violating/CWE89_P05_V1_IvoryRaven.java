import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_IvoryRaven {

    private String ivoryRavenData;

    private void queryIvoryRaven() throws SQLException {
        String data = ivoryRavenData;
        Connection ivoryRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryRaven");
        Statement ivoryRavenStatement = null;
        ResultSet ivoryRavenRows = null;
        try {
            ivoryRavenStatement = ivoryRavenConnection.createStatement();
            ivoryRavenRows = ivoryRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryRavenRows.getRow());
        } finally {
            if (ivoryRavenRows != null) {
                ivoryRavenRows.close();
            }
            if (ivoryRavenStatement != null) {
                ivoryRavenStatement.close();
            }
            ivoryRavenConnection.close();
        }
    }

    public void runIvoryRaven() throws SQLException {
        String data;
        data = System.getenv("IVORY_RAVEN_FILTER");
        ivoryRavenData = data;
        queryIvoryRaven();
    }
}
