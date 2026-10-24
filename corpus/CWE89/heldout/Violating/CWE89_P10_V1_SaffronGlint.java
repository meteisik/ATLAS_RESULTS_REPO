import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronGlint {

    public static String data;

    public void runSaffronGlint() throws SQLException {
        data = System.getenv("SAFFRON_GLINT_FILTER");
        (new CWE89_P10_V1_SaffronGlintSink()).querySaffronGlint();
    }
}

class CWE89_P10_V1_SaffronGlintSink {
    public void querySaffronGlint() throws SQLException {
        String data = CWE89_P10_V1_SaffronGlint.data;
        Connection saffronGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronGlint");
        Statement saffronGlintStatement = null;
        ResultSet saffronGlintRows = null;
        try {
            saffronGlintStatement = saffronGlintConnection.createStatement();
            saffronGlintRows = saffronGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronGlintRows.getRow());
        } finally {
            if (saffronGlintRows != null) {
                saffronGlintRows.close();
            }
            if (saffronGlintStatement != null) {
                saffronGlintStatement.close();
            }
            saffronGlintConnection.close();
        }
    }
}
