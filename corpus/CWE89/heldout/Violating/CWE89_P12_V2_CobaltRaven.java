import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltRaven {
    private static int privateFive = 5;

    public void runCobaltRaven() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("COBALT_RAVEN_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltRavenBase baseObject = new CWE89_P12_V2_CobaltRavenSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltRavenBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltRavenSink extends CWE89_P12_V2_CobaltRavenBase {
    public void action(String data) throws SQLException {
        Connection cobaltRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltRaven");
        Statement cobaltRavenStatement = null;
        ResultSet cobaltRavenRows = null;
        try {
            cobaltRavenStatement = cobaltRavenConnection.createStatement();
            cobaltRavenRows = cobaltRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltRavenRows.getRow());
        } finally {
            if (cobaltRavenRows != null) {
                cobaltRavenRows.close();
            }
            if (cobaltRavenStatement != null) {
                cobaltRavenStatement.close();
            }
            cobaltRavenConnection.close();
        }
    }
}
