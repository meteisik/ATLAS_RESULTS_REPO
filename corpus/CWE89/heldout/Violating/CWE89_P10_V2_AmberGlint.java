import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberGlint {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void runAmberGlint() throws SQLException {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_GLINT_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AmberGlintSink()).queryAmberGlint();
    }
}

class CWE89_P10_V2_AmberGlintSink {
    public void queryAmberGlint() throws SQLException {
        String data = CWE89_P10_V2_AmberGlint.data;
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
