import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_VividGlint {

    public void runVividGlint() throws SQLException {
        String data;
        data = System.getenv("VIVID_GLINT_FILTER");
        CWE89_P12_V1_VividGlintBase baseObject = new CWE89_P12_V1_VividGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_VividGlintBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_VividGlintSink extends CWE89_P12_V1_VividGlintBase {
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
