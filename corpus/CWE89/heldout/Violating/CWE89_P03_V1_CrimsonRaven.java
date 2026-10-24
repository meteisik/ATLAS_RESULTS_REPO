import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_CrimsonRaven {

    private void queryCrimsonRaven(String data) throws SQLException {
        Connection crimsonRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonRaven");
        Statement crimsonRavenStatement = null;
        ResultSet crimsonRavenRows = null;
        try {
            crimsonRavenStatement = crimsonRavenConnection.createStatement();
            crimsonRavenRows = crimsonRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonRavenRows.getRow());
        } finally {
            if (crimsonRavenRows != null) {
                crimsonRavenRows.close();
            }
            if (crimsonRavenStatement != null) {
                crimsonRavenStatement.close();
            }
            crimsonRavenConnection.close();
        }
    }

    public void runCrimsonRaven() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_RAVEN_FILTER");
        queryCrimsonRaven(data);
    }
}
