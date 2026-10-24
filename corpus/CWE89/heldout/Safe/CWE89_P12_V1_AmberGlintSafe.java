import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberGlintSafe {

    public void runAmberGlint() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_AmberGlintSafeBase baseObject = new CWE89_P12_V1_AmberGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberGlintSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberGlintSafeSink extends CWE89_P12_V1_AmberGlintSafeBase {
    public void action(String data) throws SQLException {
        Connection amberGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberGlint");
        Statement amberGlintStatement = null;
        ResultSet amberGlintRows = null;
        try {
            amberGlintStatement = amberGlintConnection.createStatement();
            amberGlintRows = amberGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberGlintRows.getRow());
        } finally {
            if (amberGlintRows != null) {
                amberGlintRows.close();
            }
            if (amberGlintStatement != null) {
                amberGlintStatement.close();
            }
            amberGlintConnection.close();
        }
    }
}
