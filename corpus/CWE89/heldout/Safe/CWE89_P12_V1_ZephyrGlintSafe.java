import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_ZephyrGlintSafe {

    public void runZephyrGlint() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_ZephyrGlintSafeBase baseObject = new CWE89_P12_V1_ZephyrGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_ZephyrGlintSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_ZephyrGlintSafeSink extends CWE89_P12_V1_ZephyrGlintSafeBase {
    public void action(String data) throws SQLException {
        Connection zephyrGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrGlint");
        Statement zephyrGlintStatement = null;
        ResultSet zephyrGlintRows = null;
        try {
            zephyrGlintStatement = zephyrGlintConnection.createStatement();
            zephyrGlintRows = zephyrGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrGlintRows.getRow());
        } finally {
            if (zephyrGlintRows != null) {
                zephyrGlintRows.close();
            }
            if (zephyrGlintStatement != null) {
                zephyrGlintStatement.close();
            }
            zephyrGlintConnection.close();
        }
    }
}
