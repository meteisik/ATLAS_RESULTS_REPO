import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_NovaMantis {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void queryNovaMantis(String data) throws SQLException {
        Connection novaMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaMantis");
        Statement novaMantisStatement = null;
        ResultSet novaMantisRows = null;
        try {
            novaMantisStatement = novaMantisConnection.createStatement();
            novaMantisRows = novaMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaMantisRows.getRow());
        } finally {
            if (novaMantisRows != null) {
                novaMantisRows.close();
            }
            if (novaMantisStatement != null) {
                novaMantisStatement.close();
            }
            novaMantisConnection.close();
        }
    }

    public void runNovaMantis() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("NOVA_MANTIS_FILTER");
        } else {
            data = null;
        }
        queryNovaMantis(data);
    }
}
