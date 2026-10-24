import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_VividGlint {

    public static String data;

    public void runVividGlint() throws SQLException {
        data = System.getenv("VIVID_GLINT_FILTER");
        (new CWE89_P10_V1_VividGlintSink()).queryVividGlint();
    }
}

class CWE89_P10_V1_VividGlintSink {
    public void queryVividGlint() throws SQLException {
        String data = CWE89_P10_V1_VividGlint.data;
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
