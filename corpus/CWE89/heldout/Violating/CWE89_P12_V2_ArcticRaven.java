import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_ArcticRaven {
    private static int privateFive = 5;

    public void runArcticRaven() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ARCTIC_RAVEN_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_ArcticRavenBase baseObject = new CWE89_P12_V2_ArcticRavenSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_ArcticRavenBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_ArcticRavenSink extends CWE89_P12_V2_ArcticRavenBase {
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
