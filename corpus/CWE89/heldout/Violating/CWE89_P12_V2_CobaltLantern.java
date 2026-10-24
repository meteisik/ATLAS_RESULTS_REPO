import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CobaltLantern {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runCobaltLantern() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_LANTERN_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CobaltLanternBase baseObject = new CWE89_P12_V2_CobaltLanternSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CobaltLanternBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CobaltLanternSink extends CWE89_P12_V2_CobaltLanternBase {
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
