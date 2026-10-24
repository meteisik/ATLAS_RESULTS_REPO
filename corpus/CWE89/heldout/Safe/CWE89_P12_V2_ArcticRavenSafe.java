import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticRavenSafe {
    private static int privateFive = 5;

    public void runArcticRaven() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticRavenSafeBase baseObject = new CWE89_P12_V2_ArcticRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticRavenSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticRavenSafeSink extends CWE89_P12_V2_ArcticRavenSafeBase {
    public void action(String data) throws SQLException {
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
