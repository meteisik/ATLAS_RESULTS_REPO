import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltLanternSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runCobaltLantern() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltLanternSafeBase baseObject = new CWE89_P12_V2_CobaltLanternSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltLanternSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltLanternSafeSink extends CWE89_P12_V2_CobaltLanternSafeBase {
    public void action(String data) throws SQLException {
        Connection cobaltLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltLantern");
        Statement cobaltLanternStatement = null;
        ResultSet cobaltLanternRows = null;
        try {
            cobaltLanternStatement = cobaltLanternConnection.createStatement();
            cobaltLanternRows = cobaltLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(cobaltLanternRows.getRow());
        } finally {
            if (cobaltLanternRows != null) {
                cobaltLanternRows.close();
            }
            if (cobaltLanternStatement != null) {
                cobaltLanternStatement.close();
            }
            cobaltLanternConnection.close();
        }
    }
}
