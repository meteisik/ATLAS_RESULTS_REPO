import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_NovaGlint {

    public void runNovaGlint() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_NovaGlintSource()).loadNovaGlint();
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
}

class CWE89_P07_V1_NovaGlintSource {
    public String loadNovaGlint() {
        String data;
        data = System.getenv("NOVA_GLINT_FILTER");
        return data;
    }
}
