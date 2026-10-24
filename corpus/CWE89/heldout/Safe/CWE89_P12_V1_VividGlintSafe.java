import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VividGlintSafe {

    public void runVividGlint() throws SQLException {
        String data;
        data = "foo";
        CWE89_P12_V1_VividGlintSafeBase baseObject = new CWE89_P12_V1_VividGlintSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VividGlintSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VividGlintSafeSink extends CWE89_P12_V1_VividGlintSafeBase {
    public void action(String data) throws SQLException {
        Connection vividGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividGlint");
        Statement vividGlintStatement = null;
        ResultSet vividGlintRows = null;
        try {
            vividGlintStatement = vividGlintConnection.createStatement();
            vividGlintRows = vividGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividGlintRows.getRow());
        } finally {
            if (vividGlintRows != null) {
                vividGlintRows.close();
            }
            if (vividGlintStatement != null) {
                vividGlintStatement.close();
            }
            vividGlintConnection.close();
        }
    }
}
