import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_NovaGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void queryNovaGlint(String data) throws SQLException {
        Connection novaGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaGlint");
        Statement novaGlintStatement = null;
        ResultSet novaGlintRows = null;
        try {
            novaGlintStatement = novaGlintConnection.createStatement();
            novaGlintRows = novaGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaGlintRows.getRow());
        } finally {
            if (novaGlintRows != null) {
                novaGlintRows.close();
            }
            if (novaGlintStatement != null) {
                novaGlintStatement.close();
            }
            novaGlintConnection.close();
        }
    }

    public void runNovaGlint() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("NOVA_GLINT_FILTER");
        } else {
            data = null;
        }
        queryNovaGlint(data);
    }
}
