import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_ArcticRavenSafe {

    public static String data;

    public void runArcticRaven() throws SQLException {
        if (5 == 5) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_ArcticRavenSafeSink()).queryArcticRaven();
    }
}

class CWE89_P10_V2_ArcticRavenSafeSink {
    public void queryArcticRaven() throws SQLException {
        String data = CWE89_P10_V2_ArcticRavenSafe.data;
        Connection arcticRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticRaven");
        Statement arcticRavenStatement = null;
        ResultSet arcticRavenRows = null;
        try {
            arcticRavenStatement = arcticRavenConnection.createStatement();
            arcticRavenRows = arcticRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticRavenRows.getRow());
        } finally {
            if (arcticRavenRows != null) {
                arcticRavenRows.close();
            }
            if (arcticRavenStatement != null) {
                arcticRavenStatement.close();
            }
            arcticRavenConnection.close();
        }
    }
}
