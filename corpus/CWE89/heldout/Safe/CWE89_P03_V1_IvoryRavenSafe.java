import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_IvoryRavenSafe {

    private void queryIvoryRaven(String data) throws SQLException {
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
        data = "foo";
        queryIvoryRaven(data);
    }
}
