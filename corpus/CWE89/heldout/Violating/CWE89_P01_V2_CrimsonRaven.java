import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_CrimsonRaven {
    private static int privateFive = 5;

    public void runCrimsonRaven() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("CRIMSON_RAVEN_FILTER");
        } else {
            data = null;
        }
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
}
