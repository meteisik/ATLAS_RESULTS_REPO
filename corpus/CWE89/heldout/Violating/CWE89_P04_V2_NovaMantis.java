import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_NovaMantis {

    private String loadNovaMantis() {
        String data;
        while (true) {
            data = System.getenv("NOVA_MANTIS_FILTER");
            break;
        }
        return data;
    }

    public void runNovaMantis() throws SQLException {
        String data = loadNovaMantis();
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
}
