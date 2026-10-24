import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_NovaMantis {

    private String novaMantisData;

    private void queryNovaMantis() throws SQLException {
        String data = novaMantisData;
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
        if (true) {
            data = System.getenv("NOVA_MANTIS_FILTER");
        } else {
            data = null;
        }
        novaMantisData = data;
        queryNovaMantis();
    }
}
