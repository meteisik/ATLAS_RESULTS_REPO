import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltRavenSafe {
    private static int privateFive = 5;

    public void runCobaltRaven() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltRavenSafeBase baseObject = new CWE89_P12_V2_CobaltRavenSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltRavenSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltRavenSafeSink extends CWE89_P12_V2_CobaltRavenSafeBase {
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
